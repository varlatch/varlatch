// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { Link, NavLink } from "react-router-dom";
import { ChevronRight } from "lucide-react";
import { Count, cn } from "./ui";

export type Crumb = { label: React.ReactNode; to?: string };

/** Slim top bar: where am I. The last crumb is the current page. */
export function Breadcrumbs({ items, className }: { items: Crumb[]; className?: string }) {
  return (
    <nav aria-label="Breadcrumb" className={cn("flex min-w-0 items-center gap-1.5 text-[13px] text-muted", className)}>
      {items.map((c, i) => {
        const last = i === items.length - 1;
        return (
          <React.Fragment key={i}>
            {i > 0 && <ChevronRight size={13} className="shrink-0 text-subtle" aria-hidden="true" />}
            {c.to && !last ? (
              <Link to={c.to} className="truncate rounded px-0.5 hover:text-fg">
                {c.label}
              </Link>
            ) : (
              <span className={cn("truncate px-0.5", last && "text-fg")} aria-current={last ? "page" : undefined}>
                {c.label}
              </span>
            )}
          </React.Fragment>
        );
      })}
    </nav>
  );
}

/**
 * Page header: breadcrumbs, title (+ badges), optional subtitle and actions,
 * and optional tabs sitting on the header's bottom border.
 */
export function PageHeader({
  breadcrumbs,
  title,
  titleClassName,
  badges,
  subtitle,
  actions,
  tabs,
  className,
}: {
  breadcrumbs?: Crumb[] | undefined;
  title: React.ReactNode;
  titleClassName?: string | undefined;
  badges?: React.ReactNode | undefined;
  subtitle?: React.ReactNode | undefined;
  actions?: React.ReactNode | undefined;
  tabs?: React.ReactNode | undefined;
  className?: string | undefined;
}) {
  return (
    <header className={cn("mb-6", className)}>
      {breadcrumbs && breadcrumbs.length > 0 && (
        <div className="-mx-8 mb-6 border-b border-bd px-8 pb-3.5">
          <Breadcrumbs items={breadcrumbs} />
        </div>
      )}
      <div className="flex flex-wrap items-start justify-between gap-x-6 gap-y-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
            <h1 className={cn("text-[26px] font-semibold leading-tight tracking-[-0.015em] text-fg", titleClassName)}>
              {title}
            </h1>
            {badges}
          </div>
          {subtitle && <div className="mt-1.5 text-sm text-muted">{subtitle}</div>}
        </div>
        {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
      </div>
      {tabs && <div className="mt-5">{tabs}</div>}
    </header>
  );
}

export type TabItem = {
  key: string;
  label: React.ReactNode;
  count?: number | undefined;
  /** Router destination; when omitted the tab calls onSelect. */
  to?: string | undefined;
  /** NavLink `end` matching for index routes. */
  end?: boolean | undefined;
  icon?: React.ReactNode | undefined;
  "data-testid"?: string | undefined;
};

/** Underline tabs. Route-driven (`to`) or state-driven (`active` + `onSelect`). */
export function Tabs({
  items,
  active,
  onSelect,
  trailing,
  className,
  "aria-label": ariaLabel,
}: {
  items: TabItem[];
  active?: string | undefined;
  onSelect?: ((key: string) => void) | undefined;
  trailing?: React.ReactNode | undefined;
  className?: string | undefined;
  "aria-label"?: string | undefined;
}) {
  const base =
    "relative -mb-px inline-flex h-10 cursor-pointer items-center gap-2 border-b-2 px-1 text-sm font-medium transition-colors";
  const on = "border-accent text-fg";
  const off = "border-transparent text-muted hover:text-fg";
  return (
    <div className={cn("flex items-end justify-between gap-4 border-b border-bd", className)}>
      <div role="tablist" aria-label={ariaLabel} className="flex min-w-0 items-end gap-6 overflow-x-auto">
        {items.map((t) => {
          const inner = (
            <>
              {t.icon}
              {t.label}
              {t.count !== undefined && <Count>{t.count}</Count>}
            </>
          );
          return t.to ? (
            <NavLink
              key={t.key}
              to={t.to}
              end={t.end ?? false}
              role="tab"
              data-testid={t["data-testid"]}
              className={({ isActive }) => cn(base, isActive ? on : off)}
            >
              {inner}
            </NavLink>
          ) : (
            <button
              key={t.key}
              type="button"
              role="tab"
              aria-selected={active === t.key}
              data-testid={t["data-testid"]}
              onClick={() => onSelect?.(t.key)}
              className={cn(base, active === t.key ? on : off)}
            >
              {inner}
            </button>
          );
        })}
      </div>
      {trailing && <div className="flex shrink-0 items-center gap-2 pb-1.5">{trailing}</div>}
    </div>
  );
}
