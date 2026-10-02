// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useCallback, useEffect, useRef, useState } from "react";
import { Search, X } from "lucide-react";
import { Kbd, cn } from "./ui";

/**
 * The house filter: instant, client-side, keyboard-first. "/" focuses it from
 * anywhere on the page, Esc clears it, ↑/↓ move through the results and ↵
 * opens the active one (with `useListNavigation`). Matches are highlighted
 * in place with <Highlight>.
 */
export const FilterInput = React.forwardRef<
  HTMLInputElement,
  {
    value: string;
    onChange: (v: string) => void;
    placeholder?: string | undefined;
    /** "4 of 8" style count; omit to hide. */
    shown?: number | undefined;
    total?: number | undefined;
    /** Noun for the count when no filter is active, e.g. "project". */
    noun?: string | undefined;
    /** Bind "/" globally to focus this input (one per page). */
    slashToFocus?: boolean | undefined;
    size?: "md" | "lg" | undefined;
    className?: string | undefined;
    onKeyDown?: ((e: React.KeyboardEvent<HTMLInputElement>) => void) | undefined;
    "data-testid"?: string | undefined;
    "aria-label"?: string | undefined;
    countTestId?: string | undefined;
  }
>(function FilterInput(
  {
    value,
    onChange,
    placeholder = "Filter…",
    shown,
    total,
    noun,
    slashToFocus = true,
    size = "md",
    className,
    onKeyDown,
    countTestId,
    ...rest
  },
  forwarded,
) {
  const inner = useRef<HTMLInputElement>(null);
  const setRefs = (el: HTMLInputElement | null) => {
    inner.current = el;
    if (typeof forwarded === "function") forwarded(el);
    else if (forwarded) forwarded.current = el;
  };

  useEffect(() => {
    if (!slashToFocus) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "/" || e.metaKey || e.ctrlKey || e.altKey) return;
      if (isTypingTarget(e.target)) return;
      e.preventDefault();
      inner.current?.focus();
      inner.current?.select();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [slashToFocus]);

  const filtering = value.trim() !== "";
  return (
    <div className={cn("flex items-center gap-3", className)}>
      <div className="relative min-w-0 flex-1">
        <Search
          size={size === "lg" ? 16 : 14}
          className={cn("pointer-events-none absolute top-1/2 -translate-y-1/2 text-muted", size === "lg" ? "left-3.5" : "left-2.5")}
        />
        <input
          ref={setRefs}
          type="text"
          value={value}
          spellCheck={false}
          autoComplete="off"
          placeholder={placeholder}
          onChange={(e) => onChange(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Escape") {
              if (value) onChange("");
              else e.currentTarget.blur();
              e.preventDefault();
              e.stopPropagation();
              return;
            }
            onKeyDown?.(e);
          }}
          {...rest}
          className={cn(
            "w-full rounded-lg border border-bd bg-inset text-fg placeholder:text-subtle transition-colors",
            "focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/20 focus-visible:outline-none hover:border-bd-strong",
            size === "lg" ? "h-11 pl-10 pr-10 text-[15px]" : "h-8 pl-8 pr-9 text-sm",
          )}
        />
        <span className={cn("absolute top-1/2 -translate-y-1/2", size === "lg" ? "right-3" : "right-2")}>
          {filtering ? (
            <button
              type="button"
              aria-label="Clear filter"
              onClick={() => {
                onChange("");
                inner.current?.focus();
              }}
              className="flex cursor-pointer items-center rounded p-0.5 text-muted hover:text-fg"
            >
              <X size={14} />
            </button>
          ) : (
            slashToFocus && <Kbd>/</Kbd>
          )}
        </span>
      </div>
      {total !== undefined && (
        <span className="shrink-0 text-[13px] tabular-nums text-muted" data-testid={countTestId}>
          {filtering && shown !== undefined
            ? `${shown} of ${total}`
            : noun
              ? `${total} ${noun}${total === 1 ? "" : "s"}`
              : total}
        </span>
      )}
    </div>
  );
});

export function isTypingTarget(target: EventTarget | null): boolean {
  const el = target as HTMLElement | null;
  if (!el) return false;
  const tag = el.tagName;
  return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || el.isContentEditable;
}

/** Case-insensitive match of every whitespace-separated term in `hay`. */
export function matchesFilter(needle: string, ...hay: (string | null | undefined)[]): boolean {
  const terms = needle.trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (terms.length === 0) return true;
  const text = hay.filter(Boolean).join(" ").toLowerCase();
  return terms.every((t) => text.includes(t));
}

/** Renders `text` with each case-insensitive occurrence of the filter's terms marked. */
export function Highlight({ text, needle, className }: { text: string; needle: string; className?: string }) {
  const terms = needle.trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (terms.length === 0) return <>{text}</>;
  const lower = text.toLowerCase();
  const marks = new Array<boolean>(text.length).fill(false);
  for (const t of terms) {
    for (let i = lower.indexOf(t); i >= 0; i = lower.indexOf(t, i + 1)) {
      for (let j = i; j < i + t.length; j++) marks[j] = true;
    }
  }
  const parts: React.ReactNode[] = [];
  let i = 0;
  while (i < text.length) {
    const on = marks[i];
    let j = i;
    while (j < text.length && marks[j] === on) j++;
    const chunk = text.slice(i, j);
    parts.push(
      on ? (
        <mark key={i} className={cn("rounded-[3px] bg-accent/20 px-px text-accent", className)}>
          {chunk}
        </mark>
      ) : (
        chunk
      ),
    );
    i = j;
  }
  return <>{parts}</>;
}

/**
 * Keyboard selection over a filtered list. Wire `onKeyDown` to the filter
 * input (↑/↓/↵) and spread `itemProps(i)` on each row.
 */
export function useListNavigation<T>(items: T[], onOpen: (item: T, e: { newTab: boolean }) => void) {
  const [active, setActive] = useState(0);
  const count = items.length;
  useEffect(() => {
    setActive((a) => (count === 0 ? 0 : Math.min(a, count - 1)));
  }, [count]);
  const listRef = useRef<HTMLElement | null>(null);
  useEffect(() => {
    listRef.current?.querySelector<HTMLElement>(`[data-nav-index="${active}"]`)?.scrollIntoView({ block: "nearest" });
  }, [active]);

  const onKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === "ArrowDown") {
        e.preventDefault();
        setActive((a) => Math.min(count - 1, a + 1));
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        setActive((a) => Math.max(0, a - 1));
      } else if (e.key === "Enter") {
        const item = items[active];
        if (item !== undefined) {
          e.preventDefault();
          onOpen(item, { newTab: e.metaKey || e.ctrlKey });
        }
      }
    },
    [items, active, count, onOpen],
  );

  const itemProps = (i: number) => ({
    "data-nav-index": i,
    "data-active": i === active || undefined,
    onMouseMove: () => setActive(i),
  });

  return { active, setActive, onKeyDown, itemProps, listRef };
}
