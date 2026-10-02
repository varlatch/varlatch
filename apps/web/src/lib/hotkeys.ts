// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useRef } from "react";
import { isTypingTarget } from "../components/FilterInput";

/**
 * Bare-key shortcuts ("?", "g p") that never fire while typing in a field or
 * while a modal dialog is open (design R2: no bare-key capture while inputs or
 * modals have focus). Sequences are space-separated: "g p".
 */
export function useHotkeys(bindings: Record<string, (e: KeyboardEvent) => void>, enabled = true): void {
  const ref = useRef(bindings);
  ref.current = bindings;
  useEffect(() => {
    if (!enabled) return;
    let pending: string | null = null;
    let timer: number | undefined;
    const onKey = (e: KeyboardEvent) => {
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      if (isTypingTarget(e.target)) return;
      if (document.querySelector('[role="dialog"][aria-modal="true"]')) return;
      const key = e.key.length === 1 ? e.key.toLowerCase() : e.key;
      const combo = pending ? `${pending} ${key}` : key;
      const handler = ref.current[combo] ?? (e.key === "?" ? ref.current["?"] : undefined);
      if (handler) {
        e.preventDefault();
        pending = null;
        handler(e);
        return;
      }
      const starts = Object.keys(ref.current).some((k) => k.startsWith(`${key} `));
      if (!pending && starts) {
        pending = key;
        window.clearTimeout(timer);
        timer = window.setTimeout(() => (pending = null), 900);
        return;
      }
      pending = null;
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
      window.clearTimeout(timer);
    };
  }, [enabled]);
}

/** Platform-appropriate modifier glyph for keycap hints. */
export function modKey(): string {
  const platform =
    (navigator as { userAgentData?: { platform?: string } }).userAgentData?.platform ?? navigator.platform;
  return /mac|iphone|ipad/i.test(platform) ? "⌘" : "Ctrl";
}
