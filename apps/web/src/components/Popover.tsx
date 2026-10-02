// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useLayoutEffect, useState } from "react";
import { createPortal } from "react-dom";

/**
 * Floating layer anchored to a trigger, rendered in a portal so cards and
 * scroll containers never clip it. Flips above the trigger when there is no
 * room below and follows scroll/resize.
 */
export function Popover({
  anchor,
  open,
  align = "start",
  matchWidth = false,
  offset = 6,
  className,
  children,
  ...props
}: Omit<React.ComponentProps<"div">, "children"> & {
  anchor: React.RefObject<HTMLElement | null>;
  open: boolean;
  align?: "start" | "end" | undefined;
  matchWidth?: boolean | undefined;
  offset?: number | undefined;
  children: React.ReactNode;
}) {
  const [pos, setPos] = useState<{ top: number; left: number; width: number; above: boolean } | null>(null);
  const layerRef = React.useRef<HTMLDivElement>(null);

  useLayoutEffect(() => {
    if (!open) return;
    const place = () => {
      const el = anchor.current;
      if (!el) return;
      const r = el.getBoundingClientRect();
      const layerHeight = layerRef.current?.offsetHeight ?? 0;
      const layerWidth = layerRef.current?.offsetWidth ?? r.width;
      const spaceBelow = window.innerHeight - r.bottom;
      const above = layerHeight > 0 && spaceBelow < layerHeight + offset + 8 && r.top > spaceBelow;
      const top = above ? r.top - layerHeight - offset : r.bottom + offset;
      let left = align === "end" ? r.right - layerWidth : r.left;
      left = Math.max(8, Math.min(left, window.innerWidth - layerWidth - 8));
      setPos({ top, left, width: r.width, above });
    };
    place();
    // Second pass once the layer has measured itself.
    const raf = requestAnimationFrame(place);
    window.addEventListener("scroll", place, true);
    window.addEventListener("resize", place);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("scroll", place, true);
      window.removeEventListener("resize", place);
    };
  }, [open, anchor, align, offset]);

  if (!open) return null;
  return createPortal(
    <div
      ref={layerRef}
      {...props}
      style={{
        position: "fixed",
        top: pos?.top ?? -9999,
        left: pos?.left ?? -9999,
        minWidth: matchWidth ? pos?.width : undefined,
        zIndex: 70,
        visibility: pos ? "visible" : "hidden",
      }}
      className={className}
    >
      {children}
    </div>,
    document.body,
  );
}
