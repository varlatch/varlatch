// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { Info } from "lucide-react";
import type { Tier } from "@varlatch/protocol";

/** Small shadcn-style primitives; Varlatch composites live in features/. */

export function cn(...parts: (string | false | undefined)[]): string {
  return parts.filter(Boolean).join(" ");
}

export function Button({
  variant = "default",
  className,
  ...props
}: React.ComponentProps<"button"> & {
  variant?: "default" | "ghost" | "danger";
}) {
  return (
    <button
      className={cn(
        "rounded-md px-3 py-1.5 text-sm font-medium transition-colors disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer focus-visible:outline-2 focus-visible:outline-accent focus-visible:outline-offset-1",
        variant === "default" && "bg-accent-dim text-fg hover:brightness-110 border border-bd",
        variant === "ghost" && "text-accent/80 hover:text-accent hover:bg-raised underline decoration-accent/30 underline-offset-2 hover:decoration-accent",
        variant === "danger" && "bg-transparent text-deny border border-deny/40 hover:bg-deny/10",
        className,
      )}
      {...props}
    />
  );
}

export function Input(props: React.ComponentProps<"input">) {
  return (
    <input
      {...props}
      className={cn(
        "rounded-md border border-bd bg-inset px-2.5 py-1.5 text-sm text-fg placeholder:text-muted focus:outline-none focus:border-accent",
        props.className,
      )}
    />
  );
}

export { Select, Menu } from "./Select";
export type { SelectOption, MenuItem } from "./Select";

const AVATAR_SIZES = { sm: "h-6 w-6 text-[10px]", md: "h-8 w-8 text-xs", lg: "h-12 w-12 text-base" };

/** Initials avatar on a deterministic name-derived hue; image wins if given. */
export function Avatar({
  name,
  image,
  size = "md",
  className,
}: {
  name: string;
  image?: string | null;
  size?: keyof typeof AVATAR_SIZES;
  className?: string;
}) {
  const initials = name
    .split(/[\s@._-]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((p) => p[0]!.toUpperCase())
    .join("") || "?";
  // Deterministic hue from the name; muted saturation/lightness so generated
  // colors sit comfortably next to the token palette in both themes.
  let hash = 0;
  for (let i = 0; i < name.length; i++) hash = (hash * 31 + name.charCodeAt(i)) | 0;
  const hue = ((hash % 360) + 360) % 360;
  if (image) {
    return (
      <img
        src={image}
        alt={name}
        title={name}
        className={cn("shrink-0 rounded-full object-cover", AVATAR_SIZES[size], className)}
      />
    );
  }
  return (
    <span
      title={name}
      aria-label={name}
      className={cn(
        "inline-flex shrink-0 select-none items-center justify-center rounded-full font-medium",
        AVATAR_SIZES[size],
        className,
      )}
      style={{
        backgroundColor: `hsl(${hue} 35% 30%)`,
        color: `hsl(${hue} 45% 88%)`,
      }}
    >
      {initials}
    </span>
  );
}

export function Card({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      className={cn("rounded-lg border border-bd bg-raised p-4", className)}
      {...props}
    />
  );
}

const TIER_CLASSES: Record<Tier, string> = {
  development: "text-tier-development border-tier-development/40",
  staging: "text-tier-staging border-tier-staging/40",
  production: "text-tier-production border-tier-production/40",
};

/** Tier is communicated by text + color, never color alone (design R1). */
export function TierChip({ tier }: { tier: Tier }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium",
        TIER_CLASSES[tier],
      )}
    >
      {tier}
    </span>
  );
}

/** Small "i" icon with a hover/focus tooltip — for explaining a section or a
    selected option. Content is plain text; keep it to a sentence or two. */
export function InfoTip({ text, className }: { text: string; className?: string }) {
  return (
    <span className={cn("relative inline-flex group align-middle", className)}>
      <span
        tabIndex={0}
        role="img"
        aria-label={text}
        className="text-muted hover:text-fg cursor-help focus-visible:outline-2 focus-visible:outline-accent rounded-sm"
      >
        <Info size={13} />
      </span>
      <span
        role="tooltip"
        className="pointer-events-none absolute left-1/2 top-full z-40 mt-1.5 w-64 -translate-x-1/2 rounded-md border border-bd bg-raised px-2.5 py-1.5 text-xs font-normal normal-case text-fg shadow-lg opacity-0 transition-opacity group-hover:opacity-100 group-focus-within:opacity-100"
      >
        {text}
      </span>
    </span>
  );
}

export function Mono({ className, ...props }: React.ComponentProps<"span">) {
  return <span className={cn("font-mono text-[13px]", className)} {...props} />;
}
