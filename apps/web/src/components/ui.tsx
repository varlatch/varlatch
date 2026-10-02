// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { Info, Loader2 } from "lucide-react";
import type { Tier } from "@varlatch/protocol";

/**
 * Design-system primitives. Every screen composes these; feature folders hold
 * Varlatch composites. Conventions:
 * - one primary (mint) action per view; destructive actions use `danger`;
 * - tier is always a dot or tint next to the tier's name, never color alone;
 * - monospace for item names, slugs, values, IDs and commands (`Mono`).
 */

export function cn(...parts: (string | false | null | undefined)[]): string {
  return parts.filter(Boolean).join(" ");
}

type ButtonVariant = "primary" | "secondary" | "ghost" | "danger" | "danger-solid" | "default";
type ButtonSize = "sm" | "md" | "lg";

const BUTTON_VARIANTS: Record<ButtonVariant, string> = {
  primary: "bg-accent text-accent-fg hover:bg-accent-strong border border-transparent font-semibold",
  default: "bg-accent text-accent-fg hover:bg-accent-strong border border-transparent font-semibold",
  secondary: "bg-raised text-fg border border-bd hover:border-bd-strong hover:bg-hover",
  ghost: "text-muted hover:text-fg hover:bg-hover border border-transparent",
  danger: "text-deny border border-deny/40 hover:bg-deny/10",
  "danger-solid": "bg-deny text-white border border-transparent hover:brightness-110 font-semibold",
};
const BUTTON_SIZES: Record<ButtonSize, string> = {
  sm: "h-7 px-2.5 text-xs gap-1.5 rounded-md",
  md: "h-8 px-3 text-sm gap-2 rounded-md",
  lg: "h-10 px-4 text-sm gap-2 rounded-lg",
};

export function Button({
  variant = "secondary",
  size = "md",
  loading = false,
  icon,
  className,
  children,
  disabled,
  ...props
}: React.ComponentProps<"button"> & {
  variant?: ButtonVariant | undefined;
  size?: ButtonSize | undefined;
  loading?: boolean | undefined;
  /** Leading icon. */
  icon?: React.ReactNode | undefined;
}) {
  return (
    <button
      type="button"
      disabled={disabled || loading}
      className={cn(
        "inline-flex shrink-0 cursor-pointer select-none items-center justify-center whitespace-nowrap transition-colors",
        "disabled:cursor-not-allowed disabled:opacity-45",
        BUTTON_VARIANTS[variant],
        BUTTON_SIZES[size],
        className,
      )}
      {...props}
    >
      {loading ? <Loader2 size={14} className="animate-spin" aria-hidden="true" /> : icon}
      {children}
    </button>
  );
}

/** Square icon-only button; `label` is required for accessibility. */
export function IconButton({
  label,
  className,
  size = "md",
  tone = "default",
  children,
  ...props
}: Omit<React.ComponentProps<"button">, "aria-label"> & {
  label: string;
  size?: "sm" | "md" | undefined;
  tone?: "default" | "danger" | undefined;
}) {
  return (
    <button
      type="button"
      aria-label={label}
      title={props.title ?? label}
      className={cn(
        "inline-flex shrink-0 cursor-pointer items-center justify-center rounded-md border border-transparent transition-colors",
        "disabled:cursor-not-allowed disabled:opacity-40",
        size === "sm" ? "size-7" : "size-8",
        tone === "danger" ? "text-muted hover:bg-deny/10 hover:text-deny" : "text-muted hover:bg-hover hover:text-fg",
        className,
      )}
      {...props}
    >
      {children}
    </button>
  );
}

export const Input = React.forwardRef<
  HTMLInputElement,
  React.ComponentProps<"input"> & { invalid?: boolean | undefined; mono?: boolean | undefined }
>(function Input({ className, invalid, mono, ...props }, ref) {
  return (
    <input
      ref={ref}
      {...props}
      aria-invalid={invalid || undefined}
      className={cn(
        "h-8 rounded-md border bg-inset px-2.5 text-sm text-fg placeholder:text-subtle transition-colors",
        "focus:outline-none focus-visible:outline-none focus:border-accent focus:ring-2 focus:ring-accent/20",
        "disabled:cursor-not-allowed disabled:opacity-50",
        invalid ? "border-deny focus:border-deny focus:ring-deny/20" : "border-bd hover:border-bd-strong",
        mono && "font-mono text-[13px]",
        className,
      )}
    />
  );
});

export const Textarea = React.forwardRef<
  HTMLTextAreaElement,
  React.ComponentProps<"textarea"> & { invalid?: boolean | undefined; mono?: boolean | undefined }
>(function Textarea({ className, invalid, mono, ...props }, ref) {
  return (
    <textarea
      ref={ref}
      {...props}
      aria-invalid={invalid || undefined}
      className={cn(
        "rounded-md border bg-inset px-2.5 py-1.5 text-sm text-fg placeholder:text-subtle transition-colors",
        "focus:outline-none focus-visible:outline-none focus:border-accent focus:ring-2 focus:ring-accent/20",
        invalid ? "border-deny" : "border-bd hover:border-bd-strong",
        mono && "font-mono text-[13px]",
        className,
      )}
    />
  );
});

/** Label + control + optional hint/error, stacked. */
export function Field({
  label,
  hint,
  error,
  htmlFor,
  className,
  children,
}: {
  label: React.ReactNode;
  hint?: React.ReactNode | undefined;
  error?: React.ReactNode | undefined;
  htmlFor?: string | undefined;
  className?: string | undefined;
  children: React.ReactNode;
}) {
  return (
    <div className={cn("space-y-1.5", className)}>
      <label htmlFor={htmlFor} className="block text-[13px] font-medium text-fg">
        {label}
      </label>
      {children}
      {error ? (
        <p className="text-xs text-deny">{error}</p>
      ) : hint ? (
        <p className="text-xs text-muted">{hint}</p>
      ) : null}
    </div>
  );
}

export { Select, Menu } from "./Select";
export type { SelectOption, MenuItem } from "./Select";

const AVATAR_SIZES = {
  xs: "size-5 text-[9px]",
  sm: "size-6 text-[10px]",
  md: "size-8 text-xs",
  lg: "size-12 text-base",
  xl: "size-16 text-xl",
};

/** Initials avatar on a deterministic name-derived hue; an image wins if given. */
export function Avatar({
  name,
  image,
  size = "md",
  className,
}: {
  name: string;
  image?: string | null | undefined;
  size?: keyof typeof AVATAR_SIZES | undefined;
  className?: string | undefined;
}) {
  const initials =
    name
      .split(/[\s@._-]+/)
      .filter(Boolean)
      .slice(0, 2)
      .map((p) => p[0]!.toUpperCase())
      .join("") || "?";
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
        "inline-flex shrink-0 select-none items-center justify-center rounded-full font-semibold",
        AVATAR_SIZES[size],
        className,
      )}
      style={{ backgroundColor: `hsl(${hue} 42% 46%)`, color: "#fff" }}
    >
      {initials}
    </span>
  );
}

export function Card({ className, ...props }: React.ComponentProps<"div">) {
  return <div className={cn("rounded-xl border border-bd bg-raised p-5", className)} {...props} />;
}

/** Card with a title row (title, optional description, trailing actions). */
export function SectionCard({
  title,
  description,
  actions,
  className,
  bodyClassName,
  children,
  ...props
}: Omit<React.ComponentProps<"section">, "title"> & {
  title: React.ReactNode;
  description?: React.ReactNode | undefined;
  actions?: React.ReactNode | undefined;
  bodyClassName?: string | undefined;
}) {
  return (
    <section className={cn("overflow-hidden rounded-xl border border-bd bg-raised", className)} {...props}>
      <header className="flex flex-wrap items-start justify-between gap-3 border-b border-bd px-5 py-4">
        <div className="min-w-0">
          <h2 className="text-[15px] font-semibold text-fg">{title}</h2>
          {description && <p className="mt-0.5 text-[13px] text-muted">{description}</p>}
        </div>
        {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
      </header>
      <div className={bodyClassName}>{children}</div>
    </section>
  );
}

const TIER_TEXT: Record<Tier, string> = {
  development: "text-tier-development",
  staging: "text-tier-staging",
  production: "text-tier-production",
};
const TIER_BG: Record<Tier, string> = {
  development: "bg-tier-development",
  staging: "bg-tier-staging",
  production: "bg-tier-production",
};

export function TierDot({ tier, className }: { tier: Tier; className?: string }) {
  return <span aria-hidden="true" className={cn("inline-block size-2 shrink-0 rounded-full", TIER_BG[tier], className)} />;
}

/** Tier is communicated by text + color, never color alone (design R1). */
export function TierChip({ tier, label, className }: { tier: Tier; label?: React.ReactNode; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border border-bd bg-inset px-2 py-0.5 text-xs font-medium text-fg",
        className,
      )}
    >
      <TierDot tier={tier} />
      {label ?? tier}
    </span>
  );
}

export function tierTextClass(tier: Tier): string {
  return TIER_TEXT[tier];
}

type BadgeTone = "neutral" | "accent" | "warn" | "danger" | "info" | "mono";
const BADGE_TONES: Record<BadgeTone, string> = {
  neutral: "border-bd text-muted",
  mono: "border-bd text-muted font-mono",
  accent: "border-accent/40 text-accent bg-accent/10",
  warn: "border-warn/40 text-warn bg-warn/10",
  danger: "border-deny/40 text-deny bg-deny/10",
  info: "border-info/40 text-info bg-info/10",
};

/** Small outlined label: kinds, types, statuses. */
export function Badge({
  tone = "neutral",
  className,
  ...props
}: React.ComponentProps<"span"> & { tone?: BadgeTone }) {
  return (
    <span
      className={cn(
        "inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-md border px-1.5 py-px text-[11px] font-medium leading-4",
        BADGE_TONES[tone],
        className,
      )}
      {...props}
    />
  );
}

type StatusTone = "ok" | "warn" | "error" | "muted" | "live";
const STATUS_DOT: Record<StatusTone, string> = {
  ok: "bg-allow",
  warn: "bg-warn",
  error: "bg-deny",
  muted: "bg-subtle",
  live: "bg-accent animate-pulse",
};
const STATUS_TEXT: Record<StatusTone, string> = {
  ok: "text-allow",
  warn: "text-warn",
  error: "text-deny",
  muted: "text-muted",
  live: "text-accent",
};

/** Dot + text status ("Healthy", "Failing", "Live"); never color alone. */
export function StatusDot({ tone, className }: { tone: StatusTone; className?: string }) {
  return <span aria-hidden="true" className={cn("inline-block size-2 shrink-0 rounded-full", STATUS_DOT[tone], className)} />;
}

export function Status({
  tone,
  children,
  className,
}: {
  tone: StatusTone;
  children: React.ReactNode;
  className?: string | undefined;
}) {
  return (
    <span className={cn("inline-flex items-center gap-1.5 text-[13px]", STATUS_TEXT[tone], className)}>
      <StatusDot tone={tone} />
      {children}
    </span>
  );
}

/** Keycap hint, e.g. ⌘K, /, ↵. */
export function Kbd({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <kbd
      className={cn(
        "inline-flex h-5 min-w-5 items-center justify-center rounded border border-bd bg-inset px-1 font-mono text-[10.5px] font-medium leading-none text-muted",
        className,
      )}
    >
      {children}
    </kbd>
  );
}

export function Mono({ className, ...props }: React.ComponentProps<"span">) {
  return <span className={cn("font-mono text-[13px]", className)} {...props} />;
}

/** Accessible on/off switch. */
export function Switch({
  checked,
  onChange,
  label,
  disabled,
  className,
  "data-testid": testId,
}: {
  checked: boolean;
  onChange: (next: boolean) => void;
  label: string;
  disabled?: boolean | undefined;
  className?: string | undefined;
  "data-testid"?: string | undefined;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      title={label}
      disabled={disabled}
      data-testid={testId}
      onClick={() => onChange(!checked)}
      className={cn(
        "relative inline-flex h-5 w-9 shrink-0 cursor-pointer items-center rounded-full border transition-colors disabled:cursor-not-allowed disabled:opacity-45",
        checked ? "border-accent bg-accent" : "border-bd-strong bg-inset",
        className,
      )}
    >
      <span
        className={cn(
          "inline-block size-3.5 rounded-full shadow transition-transform",
          checked ? "translate-x-[18px] bg-accent-fg" : "translate-x-[2px] bg-muted",
        )}
      />
    </button>
  );
}

export function Checkbox({
  checked,
  onChange,
  label,
  description,
  disabled,
  className,
  "data-testid": testId,
}: {
  checked: boolean;
  onChange: (next: boolean) => void;
  label: React.ReactNode;
  description?: React.ReactNode | undefined;
  disabled?: boolean | undefined;
  className?: string | undefined;
  "data-testid"?: string | undefined;
}) {
  return (
    <label className={cn("flex cursor-pointer items-start gap-2.5 text-sm", disabled && "cursor-not-allowed opacity-50", className)}>
      <input
        type="checkbox"
        data-testid={testId}
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
        className="mt-0.5 size-4 shrink-0 cursor-pointer rounded accent-[var(--accent)]"
      />
      <span className="min-w-0">
        <span className="block text-fg">{label}</span>
        {description && <span className="block text-xs text-muted">{description}</span>}
      </span>
    </label>
  );
}

/** Segmented control: a small set of mutually exclusive options. */
export function Segmented<T extends string>({
  value,
  onChange,
  options,
  className,
  size = "md",
  "aria-label": ariaLabel,
}: {
  value: T;
  onChange: (next: T) => void;
  options: { value: T; label: React.ReactNode; count?: number; icon?: React.ReactNode; "data-testid"?: string }[];
  className?: string | undefined;
  size?: "sm" | "md" | undefined;
  "aria-label"?: string | undefined;
}) {
  return (
    <div
      role="radiogroup"
      aria-label={ariaLabel}
      className={cn("inline-flex items-center gap-0.5 rounded-lg border border-bd bg-inset p-0.5", className)}
    >
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          role="radio"
          aria-checked={value === o.value}
          data-testid={o["data-testid"]}
          onClick={() => onChange(o.value)}
          className={cn(
            "inline-flex cursor-pointer items-center gap-1.5 rounded-md px-2.5 font-medium transition-colors",
            size === "sm" ? "h-6 text-xs" : "h-7 text-[13px]",
            value === o.value ? "bg-raised text-fg shadow-sm ring-1 ring-bd" : "text-muted hover:text-fg",
          )}
        >
          {o.icon}
          {o.label}
          {o.count !== undefined && (
            <span className="rounded bg-hover px-1 text-[11px] tabular-nums text-muted">{o.count}</span>
          )}
        </button>
      ))}
    </div>
  );
}

/** Pill counter used in tabs and headers. */
export function Count({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex h-5 min-w-5 items-center justify-center rounded-full bg-hover px-1.5 text-[11px] font-semibold tabular-nums text-muted",
        className,
      )}
    >
      {children}
    </span>
  );
}

export function Spinner({ className, size = 14 }: { className?: string; size?: number }) {
  return <Loader2 size={size} className={cn("animate-spin text-muted", className)} aria-label="Loading" />;
}

export function Skeleton({ className }: { className?: string }) {
  return <span aria-hidden="true" className={cn("block animate-pulse rounded-md bg-hover", className)} />;
}

/** Centered empty state with optional icon, description and actions. */
export function EmptyState({
  icon,
  title,
  description,
  actions,
  className,
  ...props
}: Omit<React.ComponentProps<"div">, "title"> & {
  icon?: React.ReactNode | undefined;
  title: React.ReactNode;
  description?: React.ReactNode | undefined;
  actions?: React.ReactNode | undefined;
}) {
  return (
    <div className={cn("flex flex-col items-center px-6 py-12 text-center", className)} {...props}>
      {icon && (
        <div className="mb-4 flex size-12 items-center justify-center rounded-xl border border-bd bg-inset text-muted">
          {icon}
        </div>
      )}
      <p className="text-[15px] font-semibold text-fg">{title}</p>
      {description && <p className="mt-1 max-w-md text-[13px] text-muted">{description}</p>}
      {actions && <div className="mt-5 flex items-center gap-2">{actions}</div>}
    </div>
  );
}

/** Inline callout: info, warning, danger or success. */
export function Callout({
  tone = "info",
  icon,
  title,
  children,
  actions,
  className,
  ...props
}: Omit<React.ComponentProps<"div">, "title"> & {
  tone?: "info" | "warn" | "danger" | "success" | "neutral" | undefined;
  icon?: React.ReactNode | undefined;
  title?: React.ReactNode | undefined;
  actions?: React.ReactNode | undefined;
}) {
  const tones = {
    info: "border-info/30 bg-info/[0.06] text-fg",
    warn: "border-warn/40 bg-warn/[0.07] text-fg",
    danger: "border-deny/40 bg-deny/[0.07] text-fg",
    success: "border-accent/40 bg-accent/[0.07] text-fg",
    neutral: "border-bd bg-inset text-fg",
  } as const;
  const iconTone = {
    info: "text-info",
    warn: "text-warn",
    danger: "text-deny",
    success: "text-accent",
    neutral: "text-muted",
  } as const;
  return (
    <div className={cn("flex items-start gap-3 rounded-lg border px-4 py-3 text-[13px]", tones[tone], className)} {...props}>
      {icon && <span className={cn("mt-0.5 shrink-0", iconTone[tone])}>{icon}</span>}
      <div className="min-w-0 flex-1">
        {title && <p className="font-medium">{title}</p>}
        {children && <div className={cn(title ? "mt-0.5 text-muted" : "text-fg/90")}>{children}</div>}
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </div>
  );
}

/** Small "i" icon with a hover/focus tooltip. Plain text, a sentence or two. */
export function InfoTip({ text, className }: { text: string; className?: string }) {
  return (
    <span className={cn("group relative inline-flex align-middle", className)}>
      <span
        tabIndex={0}
        role="img"
        aria-label={text}
        className="cursor-help rounded-sm text-subtle hover:text-fg focus-visible:outline-2 focus-visible:outline-accent"
      >
        <Info size={13} />
      </span>
      <span
        role="tooltip"
        className="pointer-events-none absolute left-1/2 top-full z-40 mt-1.5 w-64 -translate-x-1/2 rounded-lg border border-bd bg-raised px-3 py-2 text-xs font-normal normal-case leading-relaxed text-fg opacity-0 shadow-pop transition-opacity group-focus-within:opacity-100 group-hover:opacity-100"
      >
        {text}
      </span>
    </span>
  );
}

/** Table styling helpers: consistent header, row and cell rhythm. */
export const table = {
  wrap: "overflow-x-auto",
  table: "w-full border-collapse text-sm",
  th: "h-9 border-b border-bd px-4 text-left text-xs font-medium text-muted whitespace-nowrap",
  tr: "border-b border-bd last:border-b-0 transition-colors",
  trHover: "hover:bg-hover/60",
  td: "h-12 px-4 align-middle",
};
