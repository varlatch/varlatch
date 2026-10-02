// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useEffect, useState } from "react";
import { ArrowRight, Bot, BookOpen, ChevronDown, CircleMinus, KeyRound, ScrollText, ShieldCheck, User, Users, type LucideIcon } from "lucide-react";
import { cn } from "../../components/ui";

const SEEN_KEY = "varlatch:access-explainer-seen";

/**
 * The access model at a glance: who → bundles → grants → every request →
 * audit, with requirements and capabilities hanging off the request check
 * as narrowing-only mechanisms. Open on the first visit, collapsed after.
 */
export function HowAccessWorks() {
  // Open on the very first visit only; after that it starts collapsed.
  const [open, setOpen] = useState(() => localStorage.getItem(SEEN_KEY) !== "1");
  useEffect(() => localStorage.setItem(SEEN_KEY, "1"), []);
  const toggle = () => setOpen((v) => !v);
  return (
    <section data-testid="how-access-works" className="mb-6 overflow-hidden rounded-xl border border-bd bg-raised">
      <button
        type="button"
        data-testid="how-access-works-toggle"
        aria-expanded={open}
        onClick={toggle}
        className="flex w-full cursor-pointer items-center gap-3 px-5 py-3.5 text-left hover:bg-hover/50"
      >
        <BookOpen size={17} className="text-accent" aria-hidden="true" />
        <span className="font-semibold">How access works</span>
        {!open && <span className="text-[13px] text-muted">The model in five steps</span>}
        <span className="flex-1" />
        <span className="inline-flex items-center gap-1 text-[13px] text-muted">
          {open ? "Hide" : "Show"}
          <ChevronDown size={15} className={cn("transition-transform", open && "rotate-180")} />
        </span>
      </button>
      {open && (
        <div className="border-t border-bd px-5 pb-5 pt-5">
          <div className="grid grid-cols-2 items-stretch gap-2 sm:grid-cols-3 lg:grid-cols-[1fr_auto_1fr_auto_1fr_auto_1fr_auto_1fr]">
            <Node tone="info" title="Who" icons={[User, Bot]} text="People and machines. Machines start with zero access; people get their role's built-in grants." />
            <Arrow />
            <Node tone="warn" title="Bundles" icons={[Users]} text="Roles, groups and teams. Fewer grants, no extra power." />
            <Arrow />
            <Node tone="accent" title="Grants" icons={[KeyRound]} text="Who, what and where. Explicit, or built into the Admin and Member roles." highlight />
            <Arrow />
            <Node tone="danger" title="Every request" icons={[ShieldCheck]} text="Checked fresh. Revoking takes effect on the next request." />
            <Arrow />
            <Node tone="info" title="Audit" icons={[ScrollText]} text="Every allow and every deny is recorded." />
          </div>
          <div className="mt-2 grid grid-cols-1 lg:grid-cols-[1fr_auto_1fr_auto_1fr_auto_1fr_auto_1fr]">
            <div className="hidden lg:col-span-6 lg:block" />
            <div className="flex flex-col items-center lg:col-span-1">
              <span className="hidden h-4 w-px border-l border-dashed border-bd-strong lg:block" aria-hidden="true" />
              <div className="flex items-center gap-2.5 rounded-lg border border-dashed border-bd-strong px-3 py-2 text-[12.5px]">
                <CircleMinus size={15} className="shrink-0 text-muted" />
                <span>
                  <span className="font-medium text-fg">Requirements and capabilities</span>
                  <span className="block text-muted">can only narrow access, never grant it</span>
                </span>
              </div>
            </div>
          </div>
          <div className="mt-5 flex flex-wrap items-center gap-2 rounded-lg border border-bd bg-inset px-4 py-3 text-[13px] text-muted">
            <span className="mr-1">Example:</span>
            <Chip tone="info">github-actions-api</Chip>
            can
            <Chip tone="accent">Read config + use secrets</Chip>
            on
            <Chip tone="warn">api</Chip>
            in
            <Chip tone="danger">all environments</Chip>
          </div>
        </div>
      )}
    </section>
  );
}

const TONES = {
  info: "border-info/50 text-info",
  warn: "border-warn/50 text-warn",
  accent: "border-accent/60 text-accent",
  danger: "border-tier-production/50 text-tier-production",
} as const;

function Node({
  title,
  text,
  icons,
  tone,
  highlight,
}: {
  title: string;
  text: string;
  icons: LucideIcon[];
  tone: keyof typeof TONES;
  highlight?: boolean;
}) {
  return (
    <div
      className={cn(
        "flex flex-col items-center rounded-xl border bg-raised px-4 py-4 text-center",
        highlight ? "border-accent/70 bg-accent/[0.05] ring-1 ring-accent/30" : "border-bd",
      )}
    >
      <span className={cn("mb-2 flex items-center gap-2", TONES[tone].split(" ").pop())}>
        {icons.map((Icon, i) => (
          <Icon key={i} size={22} />
        ))}
      </span>
      <span className="font-semibold text-fg">{title}</span>
      <span className="mt-1 text-[12.5px] leading-snug text-muted">{text}</span>
    </div>
  );
}

function Arrow() {
  return (
    <div className="hidden items-center justify-center text-subtle lg:flex" aria-hidden="true">
      <ArrowRight size={18} />
    </div>
  );
}

function Chip({ tone, children }: { tone: keyof typeof TONES; children: React.ReactNode }) {
  return <span className={cn("rounded-md border bg-raised px-2 py-0.5 font-mono text-[12.5px]", TONES[tone])}>{children}</span>;
}
