// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Archive, ArrowUpRight, ChevronDown, CircleCheck, Monitor, Moon, Palette, Server, Settings2, Sun, TriangleAlert } from "lucide-react";
import { useOrgRealtime } from "../../lib/realtime";
import { useSession } from "../../lib/session";
import { SOURCE_REPOSITORY, sourceUrl } from "../../lib/source";
import { chooseThemePreference, themePreference, type ThemePreference } from "../../lib/theme";
import { timeAgo, useNow } from "../../lib/time";
import { Badge, Button, Input, Mono, SectionCard, cn } from "../../components/ui";
import { CopyButton } from "../../components/CodeBlock";
import { PageHeader } from "../../components/PageHeader";
import { useToast } from "../../components/Toast";
import { errorMessage } from "../../shell/Shell";
import { useCapability, useMeta, useOrgName } from "../projects/hooks";
import { backupHealth } from "../installation/backupHealth";

/** Organization settings and facts about this installation. */

const SECTIONS = [
  { id: "general", label: "General", icon: Settings2 },
  { id: "server", label: "Server", icon: Server },
  { id: "backups", label: "Backups", icon: Archive },
  { id: "appearance", label: "Appearance", icon: Palette },
] as const;

export function SettingsPage() {
  const { org } = useParams() as { org: string };
  const { api } = useSession();
  useOrgRealtime(org, ["organization"], [["org", org], ["orgs"]]);
  const orgName = useOrgName(org);
  const orgQuery = useQuery({ queryKey: ["org", org], queryFn: () => api.getOrganization(org) });
  const backups = useQuery({ queryKey: ["installation-backups"], queryFn: () => api.getInstallationBackups(), retry: false, refetchInterval: 60_000 });
  const [active, setActive] = useState<string>("general");

  // Highlight the section in view.
  useEffect(() => {
    const els = SECTIONS.map((s) => document.getElementById(`settings-${s.id}`)).filter(Boolean) as HTMLElement[];
    const io = new IntersectionObserver(
      (entries) => {
        const top = entries.filter((e) => e.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)[0];
        if (top) setActive(top.target.id.replace("settings-", ""));
      },
      { rootMargin: "-20% 0px -60% 0px" },
    );
    els.forEach((el) => io.observe(el));
    return () => io.disconnect();
  }, [backups.data]);

  const sections = SECTIONS.filter((s) => s.id !== "backups" || backups.data);

  return (
    <>
      <PageHeader breadcrumbs={[{ label: orgName, to: `/o/${org}/projects` }, { label: "Settings" }]} title="Settings" />
      <div className="grid gap-8 lg:grid-cols-[200px_1fr]">
        <nav className="hidden lg:block" aria-label="Settings sections">
          <ul className="sticky top-6 space-y-0.5">
            {sections.map(({ id, label, icon: Icon }) => (
              <li key={id}>
                <a
                  href={`#settings-${id}`}
                  onClick={(e) => {
                    e.preventDefault();
                    document.getElementById(`settings-${id}`)?.scrollIntoView({ behavior: "smooth", block: "start" });
                    setActive(id);
                  }}
                  className={cn(
                    "relative flex h-9 items-center gap-2.5 rounded-lg px-3 text-[14px] font-medium transition-colors",
                    active === id ? "bg-accent-dim text-fg" : "text-muted hover:bg-hover hover:text-fg",
                  )}
                >
                  {active === id && <span className="absolute inset-y-1.5 left-0 w-[3px] rounded-r bg-accent" aria-hidden="true" />}
                  <Icon size={16} className={active === id ? "text-accent" : undefined} />
                  {label}
                </a>
              </li>
            ))}
          </ul>
        </nav>
        <div className="min-w-0 space-y-6">
          <OrganizationCard org={org} name={orgQuery.data?.name} slug={orgQuery.data?.slug} id={orgQuery.data?.id} />
          <ServerCard />
          {backups.data && <BackupsSummary data={backups.data} />}
          <AppearanceCard />
        </div>
      </div>
    </>
  );
}

function Row({ label, hint, children }: { label: string; hint?: string | undefined; children: React.ReactNode }) {
  return (
    <div className="grid items-center gap-x-6 gap-y-1.5 border-b border-bd px-5 py-3.5 last:border-b-0 sm:grid-cols-[180px_1fr]">
      <div>
        <p className="text-[13px] font-medium">{label}</p>
        {hint && <p className="text-xs text-muted">{hint}</p>}
      </div>
      <div className="min-w-0">{children}</div>
    </div>
  );
}

function OrganizationCard({ org, name, slug, id }: { org: string; name: string | undefined; slug: string | undefined; id: string | undefined }) {
  const { api } = useSession();
  const qc = useQueryClient();
  const toast = useToast();
  const canRename = useCapability("organizations.rename");
  const [draft, setDraft] = useState<string | null>(null);
  const value = draft ?? name ?? "";
  const rename = useMutation({
    mutationFn: () => api.renameOrganization(org, value.trim()),
    onSuccess: async (updated) => {
      setDraft(null);
      await Promise.all([qc.invalidateQueries({ queryKey: ["orgs"] }), qc.invalidateQueries({ queryKey: ["org", org] })]);
      toast.success("Organization renamed", { description: updated.name });
    },
    onError: (err) => toast.error("Could not rename the organization", { description: errorMessage(err) }),
  });
  const dirty = draft !== null && draft.trim() !== "" && draft.trim() !== name;
  return (
    <SectionCard id="settings-general" title="Organization" description="How this organization appears, and the identifiers the CLI and URLs use." className="scroll-mt-6" data-testid="settings-organization">
      <Row label="Name" hint={canRename ? "Display name; the slug never changes." : undefined}>
        {canRename ? (
          <form
            className="flex items-center gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              if (dirty) rename.mutate();
            }}
          >
            <Input data-testid="org-name" className="w-full max-w-sm" value={value} onChange={(e) => setDraft(e.target.value)} />
            <Button type="submit" variant={dirty ? "primary" : "secondary"} disabled={!dirty} loading={rename.isPending} data-testid="save-org-name">
              Save
            </Button>
          </form>
        ) : (
          <span>{name}</span>
        )}
      </Row>
      <Row label="Slug" hint="Used in URLs and CLI commands">
        {slug && (
          <span className="inline-flex items-center gap-1.5">
            <Mono className="rounded-md border border-bd bg-inset px-2 py-1">{slug}</Mono>
            <CopyButton value={slug} label="Copy slug" />
          </span>
        )}
      </Row>
      <Row label="ID">
        {id && (
          <span className="inline-flex items-center gap-1.5">
            <Mono className="rounded-md border border-bd bg-inset px-2 py-1 text-muted">{id}</Mono>
            <CopyButton value={id} label="Copy ID" />
          </span>
        )}
      </Row>
    </SectionCard>
  );
}

function ServerCard() {
  const meta = useMeta();
  const [showCaps, setShowCaps] = useState(false);
  const caps = meta.data?.capabilities ?? [];
  return (
    <SectionCard id="settings-server" title="Server" description="Facts this installation reports. Nothing here is editable from the dashboard." className="scroll-mt-6" data-testid="settings-server">
      <Row label="Version">
        <Mono className="rounded-md border border-bd bg-inset px-2 py-1">{meta.data?.serverVersion ?? "…"}</Mono>
      </Row>
      <Row label="Source code" hint="Server and dashboard: AGPL-3.0-or-later. CLI and SDKs: Apache-2.0.">
        <a
          href={sourceUrl(meta.data?.serverVersion)}
          target="_blank"
          rel="noreferrer"
          data-testid="source-link"
          className="inline-flex items-center gap-1 text-[13px] text-accent hover:underline"
        >
          {SOURCE_REPOSITORY.replace(/^https:\/\//, "")}
          <ArrowUpRight size={13} />
        </a>
      </Row>
      <Row label="API">
        <Mono>{meta.data ? `v${meta.data.apiMajor}` : "…"}</Mono>
      </Row>
      <Row label="Capabilities" hint="Features this server supports">
        <div>
          <button
            type="button"
            data-testid="toggle-capabilities"
            onClick={() => setShowCaps((v) => !v)}
            className="inline-flex cursor-pointer items-center gap-2 text-[13px] text-fg hover:text-accent"
          >
            <Badge className="font-mono">{caps.length} enabled</Badge>
            {showCaps ? "Hide" : "Show"}
            <ChevronDown size={13} className={cn("transition-transform", showCaps && "rotate-180")} />
          </button>
          {showCaps && (
            <div className="mt-3 flex flex-wrap gap-1.5">
              {caps.map((c) => (
                <Badge key={c} className="font-mono">
                  {c}
                </Badge>
              ))}
            </div>
          )}
        </div>
      </Row>
    </SectionCard>
  );
}

function BackupsSummary({ data }: { data: Parameters<typeof backupHealth>[0] }) {
  const now = useNow();
  const health = backupHealth(data, now);
  return (
    <SectionCard
      id="settings-backups"
      title="Backups"
      description="Encrypted archives of this whole installation, run by your operator."
      className="scroll-mt-6"
      data-testid="settings-backups"
      actions={
        <Link to="/installation/settings" className="inline-flex h-7 items-center rounded-md border border-bd px-2.5 text-xs font-medium text-fg hover:bg-hover">
          Installation settings
        </Link>
      }
    >
      <div className="flex flex-wrap items-center gap-x-8 gap-y-3 px-5 py-4">
        <span className="flex items-center gap-3">
          {health.tone === "ok" ? <CircleCheck size={20} className="text-accent" /> : <TriangleAlert size={20} className={health.tone === "error" ? "text-deny" : "text-warn"} />}
          <span>
            <span className="block text-[14px] font-medium">{health.headline}</span>
            <span className="block text-xs text-muted">{health.detail}</span>
          </span>
        </span>
        <span className="flex-1" />
        <span className="flex items-center gap-3 text-xs text-muted">
          Last 7 days
          <span className="flex gap-1" aria-label="Archives per day, last 7 days">
            {health.lastWeek.map((d) => (
              <span
                key={d.day}
                title={`${d.day}: ${d.count} archive${d.count === 1 ? "" : "s"}`}
                className={cn("size-3.5 rounded-[3px]", d.count > 0 ? "bg-accent" : "border border-bd bg-inset")}
              />
            ))}
          </span>
        </span>
      </div>
      {data.archives[0] && (
        <p className="border-t border-bd px-5 py-2.5 text-xs text-muted">
          Latest archive {timeAgo(data.archives[0].createdAt, now)}
          {data.archives[0].delivery ? ` · delivered to ${data.archives[0].delivery.destination}` : " · not delivered off-host"}
        </p>
      )}
    </SectionCard>
  );
}

function AppearanceCard() {
  const [pref, setPref] = useState<ThemePreference>(themePreference);
  useEffect(() => {
    const on = (e: Event) => setPref((e as CustomEvent<ThemePreference>).detail);
    window.addEventListener("varlatch:theme-preference", on);
    return () => window.removeEventListener("varlatch:theme-preference", on);
  }, []);
  return (
    <SectionCard id="settings-appearance" title="Appearance" description="Stored in this browser only; everyone picks their own." className="scroll-mt-6" data-testid="settings-appearance">
      <div className="px-5 py-4">
        <ThemePicker value={pref} onChange={(p) => chooseThemePreference(p)} />
      </div>
    </SectionCard>
  );
}

/** Three preview tiles: Dark, Light, System. */
export function ThemePicker({ value, onChange }: { value: ThemePreference; onChange: (p: ThemePreference) => void }) {
  const options: { value: ThemePreference; label: string; icon: React.ReactNode }[] = [
    { value: "dark", label: "Dark", icon: <Moon size={14} /> },
    { value: "light", label: "Light", icon: <Sun size={14} /> },
    { value: "system", label: "System", icon: <Monitor size={14} /> },
  ];
  return (
    <div role="radiogroup" aria-label="Theme" className="grid max-w-2xl gap-3 sm:grid-cols-3">
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          role="radio"
          aria-checked={value === o.value}
          data-testid={`theme-${o.value}`}
          onClick={() => onChange(o.value)}
          className={cn(
            "cursor-pointer overflow-hidden rounded-xl border text-left transition-colors",
            value === o.value ? "border-accent ring-1 ring-accent/40" : "border-bd hover:border-bd-strong",
          )}
        >
          <ThemeThumb kind={o.value} />
          <span className="flex items-center gap-2 border-t border-bd px-3 py-2 text-[13px] font-medium">
            <span className={cn("flex size-4 items-center justify-center rounded-full border", value === o.value ? "border-accent" : "border-bd-strong")}>
              {value === o.value && <span className="size-2 rounded-full bg-accent" />}
            </span>
            {o.icon}
            {o.label}
          </span>
        </button>
      ))}
    </div>
  );
}

function ThemeThumb({ kind }: { kind: ThemePreference }) {
  const dark = { bg: "#0d0f14", side: "#151821", line: "#262b38", accent: "#7bd88f" };
  const light = { bg: "#f6f7f9", side: "#ffffff", line: "#dde1e8", accent: "#1a7f37" };
  const pane = (c: typeof dark) => (
    <div className="flex h-full w-full" style={{ background: c.bg }}>
      <div className="w-1/4 space-y-1 border-r p-1.5" style={{ background: c.side, borderColor: c.line }}>
        <div className="h-1.5 w-3/4 rounded-sm" style={{ background: c.accent }} />
        <div className="h-1 w-2/3 rounded-sm" style={{ background: c.line }} />
        <div className="h-1 w-1/2 rounded-sm" style={{ background: c.line }} />
      </div>
      <div className="flex-1 space-y-1.5 p-2">
        <div className="h-1.5 w-1/3 rounded-sm" style={{ background: c.line }} />
        <div className="h-5 rounded border" style={{ borderColor: c.line, background: c.side }} />
        <div className="h-5 rounded border" style={{ borderColor: c.line, background: c.side }} />
      </div>
    </div>
  );
  return (
    <div className="h-24 overflow-hidden">
      {kind === "system" ? (
        <div className="relative h-full">
          {pane(dark)}
          <div className="absolute inset-0" style={{ clipPath: "polygon(55% 0, 100% 0, 100% 100%, 45% 100%)" }}>
            {pane(light)}
          </div>
        </div>
      ) : (
        pane(kind === "dark" ? dark : light)
      )}
    </div>
  );
}

