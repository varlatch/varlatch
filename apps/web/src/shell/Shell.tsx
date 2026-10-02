// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useEffect, useState } from "react";
import { Link, NavLink, Outlet, useLocation, useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Building2,
  Check,
  ChevronsUpDown,
  FolderClosed,
  LogOut,
  Moon,
  PanelLeftClose,
  PanelLeftOpen,
  Plug,
  Plus,
  ScrollText,
  Search,
  Server,
  Settings,
  Sun,
  Users,
} from "lucide-react";
import { useSession } from "../lib/session";
import { displayEmail } from "../lib/identity";
import { applyTheme, initialTheme, type Theme } from "../lib/theme";
import { modKey, useHotkeys } from "../lib/hotkeys";
import { Avatar, Field, Input, Kbd, cn } from "../components/ui";
import { Menu } from "../components/Select";
import { Dialog } from "../components/Dialog";
import { Button } from "../components/ui";
import { CommandPalette } from "../components/CommandPalette";
import { ShortcutsDialog } from "./ShortcutsDialog";
import { BrandMark } from "./BrandMark";

const LAST_ORG_KEY = "varlatch:last-org";
const SIDEBAR_KEY = "varlatch:sidebar";

/** The org in the URL, else the last one visited (account and installation pages). */
export function useCurrentOrg(): string | undefined {
  const { org } = useParams();
  const { api } = useSession();
  const orgs = useQuery({ queryKey: ["orgs"], queryFn: () => api.listOrganizations() });
  if (org) return org;
  const remembered = localStorage.getItem(LAST_ORG_KEY);
  const items = orgs.data?.items ?? [];
  if (remembered && items.some((o) => o.slug === remembered)) return remembered;
  return items[0]?.slug;
}

export function rememberOrg(slug: string): void {
  localStorage.setItem(LAST_ORG_KEY, slug);
}

export function lastOrg(): string | null {
  return localStorage.getItem(LAST_ORG_KEY);
}

const NAV = [
  { to: "projects", label: "Projects", icon: FolderClosed, key: "p" },
  { to: "access", label: "Access", icon: Users, key: "a" },
  { to: "connections", label: "Connections", icon: Plug, key: "c" },
  { to: "audit", label: "Audit", icon: ScrollText, key: "l" },
  { to: "settings", label: "Settings", icon: Settings, key: "s" },
] as const;

function useNarrow(): boolean {
  const query = "(max-width: 1023px)";
  const [narrow, setNarrow] = useState(() => matchMedia(query).matches);
  useEffect(() => {
    const mq = matchMedia(query);
    const on = () => setNarrow(mq.matches);
    mq.addEventListener("change", on);
    return () => mq.removeEventListener("change", on);
  }, []);
  return narrow;
}

export function Shell() {
  const org = useCurrentOrg();
  const { org: orgParam } = useParams();
  const navigate = useNavigate();
  const location = useLocation();
  const narrow = useNarrow();
  const [pinnedCollapsed, setPinnedCollapsed] = useState(() => localStorage.getItem(SIDEBAR_KEY) === "collapsed");
  const collapsed = narrow || pinnedCollapsed;
  const [shortcutsOpen, setShortcutsOpen] = useState(false);

  useEffect(() => {
    if (orgParam) rememberOrg(orgParam);
  }, [orgParam]);

  useHotkeys(
    {
      "?": () => setShortcutsOpen(true),
      ...Object.fromEntries(NAV.map((n) => [`g ${n.key}`, () => org && navigate(`/o/${org}/${n.to}`)])),
      "g m": () => navigate("/account"),
    },
    true,
  );

  // Keep scroll position sane between pages.
  useEffect(() => {
    window.scrollTo({ top: 0 });
  }, [location.pathname]);

  return (
    <div className="flex min-h-screen">
      <aside
        className={cn(
          "sticky top-0 flex h-screen shrink-0 flex-col border-r border-bd bg-raised transition-[width] duration-150",
          collapsed ? "w-16" : "w-[248px]",
        )}
      >
        <div className={cn("flex items-center pt-4", collapsed ? "justify-center px-2" : "justify-between px-4")}>
          <Link
            to={org ? `/o/${org}/projects` : "/"}
            className="flex items-center gap-2.5 rounded-md"
            aria-label="Varlatch home"
          >
            <BrandMark size={collapsed ? 30 : 28} />
            {!collapsed && <span className="text-[17px] font-semibold tracking-[-0.01em]">Varlatch</span>}
          </Link>
          {!collapsed && !narrow && (
            <button
              type="button"
              aria-label="Collapse sidebar"
              title="Collapse sidebar"
              onClick={() => {
                setPinnedCollapsed(true);
                localStorage.setItem(SIDEBAR_KEY, "collapsed");
              }}
              className="cursor-pointer rounded-md p-1 text-subtle hover:bg-hover hover:text-fg"
            >
              <PanelLeftClose size={16} />
            </button>
          )}
        </div>

        <div className={cn("space-y-2 pt-4", collapsed ? "px-2" : "px-3")}>
          <OrgSwitcher org={org} collapsed={collapsed} />
          <button
            type="button"
            data-testid="nav-search"
            onClick={() => window.dispatchEvent(new CustomEvent("varlatch:open-palette"))}
            title={`Search (${modKey()} K)`}
            aria-label="Search"
            className={cn(
              "flex h-9 w-full cursor-pointer items-center gap-2.5 rounded-lg border border-bd bg-inset text-sm text-muted transition-colors hover:border-bd-strong hover:text-fg",
              collapsed ? "justify-center" : "px-3",
            )}
          >
            <Search size={15} />
            {!collapsed && (
              <>
                <span className="flex-1 text-left">Search…</span>
                <Kbd>{modKey() === "⌘" ? "⌘K" : "Ctrl K"}</Kbd>
              </>
            )}
          </button>
        </div>

        <nav className={cn("flex-1 space-y-0.5 overflow-y-auto pt-4", collapsed ? "px-2" : "px-3")} aria-label="Main">
          {org &&
            NAV.map(({ to, label, icon: Icon }) => (
              <NavLink
                key={to}
                to={`/o/${org}/${to}`}
                title={collapsed ? label : undefined}
                className={({ isActive }) =>
                  cn(
                    "group relative flex h-9 items-center gap-3 rounded-lg text-[14px] font-medium transition-colors",
                    collapsed ? "justify-center" : "px-3",
                    isActive ? "bg-accent-dim text-fg" : "text-muted hover:bg-hover hover:text-fg",
                  )
                }
              >
                {({ isActive }) => (
                  <>
                    {isActive && <span className="absolute inset-y-1.5 left-0 w-[3px] rounded-r bg-accent" aria-hidden="true" />}
                    <Icon size={17} className={cn(isActive ? "text-accent" : "text-muted group-hover:text-fg")} />
                    {!collapsed && label}
                  </>
                )}
              </NavLink>
            ))}
          {collapsed && !narrow && (
            <button
              type="button"
              aria-label="Expand sidebar"
              title="Expand sidebar"
              onClick={() => {
                setPinnedCollapsed(false);
                localStorage.removeItem(SIDEBAR_KEY);
              }}
              className="mt-2 flex h-9 w-full cursor-pointer items-center justify-center rounded-lg text-subtle hover:bg-hover hover:text-fg"
            >
              <PanelLeftOpen size={16} />
            </button>
          )}
        </nav>

        <UserFooter collapsed={collapsed} />
      </aside>

      <main className="min-w-0 flex-1">
        <div className="mx-auto w-full max-w-[1480px] px-8 pb-24 pt-3.5">
          <Outlet />
        </div>
      </main>
      <CommandPalette />
      <ShortcutsDialog open={shortcutsOpen} onClose={() => setShortcutsOpen(false)} />
    </div>
  );
}

function OrgSwitcher({ org, collapsed }: { org: string | undefined; collapsed: boolean }) {
  const { api } = useSession();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const orgs = useQuery({ queryKey: ["orgs"], queryFn: () => api.listOrganizations() });
  const installation = useQuery({
    queryKey: ["installation-backups"],
    queryFn: () => api.getInstallationBackups(),
    retry: false,
  });
  const current = orgs.data?.items.find((o) => o.slug === org);
  const [creating, setCreating] = useState(false);

  return (
    <>
      <Menu
        data-testid="org-switcher"
        label="Switch organization"
        align="start"
        width="w-60"
        className="block w-full"
        buttonClassName={cn(
          "h-10 w-full rounded-lg border border-bd bg-raised text-fg hover:border-bd-strong hover:bg-hover",
          collapsed ? "justify-center" : "justify-between gap-2 px-3",
        )}
        header={<p className="text-[11px] font-medium uppercase tracking-wider text-subtle">Organizations</p>}
        items={[
          ...(orgs.data?.items ?? []).map((o) => ({
            label: o.name,
            icon: <Building2 size={15} />,
            hint: o.slug === org ? <Check size={14} className="text-accent" /> : undefined,
            onSelect: () => navigate(`/o/${o.slug}/projects`),
            "data-testid": `org-option-${o.slug}`,
          })),
          {
            label: "New organization…",
            icon: <Plus size={15} />,
            separatorBefore: true,
            onSelect: () => setCreating(true),
            "data-testid": "org-create",
          },
          ...(installation.data
            ? [
                {
                  label: "Installation settings",
                  icon: <Server size={15} />,
                  onSelect: () => navigate("/installation/settings"),
                  "data-testid": "installation-settings-link",
                },
              ]
            : []),
        ]}
      >
        {collapsed ? (
          <Building2 size={16} className="text-muted" />
        ) : (
          <>
            <span className="flex min-w-0 items-center gap-2.5">
              <Building2 size={16} className="shrink-0 text-muted" />
              <span className="truncate text-[14px] font-medium" data-testid="org-switcher-name">
                {current?.name ?? org ?? "…"}
              </span>
            </span>
            <ChevronsUpDown size={14} className="shrink-0 text-muted" />
          </>
        )}
      </Menu>
      <NewOrgDialog
        open={creating}
        onClose={() => setCreating(false)}
        onCreated={async (slug) => {
          setCreating(false);
          await qc.invalidateQueries({ queryKey: ["orgs"] });
          navigate(`/o/${slug}/projects`);
        }}
      />
    </>
  );
}

export function slugify(name: string): string {
  return name
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[̀-ͯ]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 63);
}

export function NewOrgDialog({
  open,
  onClose,
  onCreated,
}: {
  open: boolean;
  onClose: () => void;
  onCreated: (slug: string) => void;
}) {
  const { api } = useSession();
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [slugTouched, setSlugTouched] = useState(false);
  const effectiveSlug = slugTouched ? slug : slugify(name);
  const create = useMutation({
    mutationFn: () => api.createOrganization({ slug: effectiveSlug, name: name.trim() || effectiveSlug }),
    onSuccess: (org) => {
      setName("");
      setSlug("");
      setSlugTouched(false);
      onCreated(org.slug);
    },
  });
  return (
    <Dialog
      open={open}
      onClose={onClose}
      size="sm"
      title="New organization"
      description="Organizations hold projects, people and machines. Nothing is shared between them."
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant="primary"
            data-testid="create-org"
            loading={create.isPending}
            disabled={!effectiveSlug}
            onClick={() => create.mutate()}
          >
            Create organization
          </Button>
        </>
      }
    >
      <form
        className="space-y-4"
        onSubmit={(e) => {
          e.preventDefault();
          if (effectiveSlug) create.mutate();
        }}
      >
        <Field label="Name">
          <Input data-autofocus data-testid="new-org-name" className="w-full" value={name} placeholder="Acme" onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label="Slug" hint="Used in URLs and CLI commands. It cannot be changed later.">
          <Input
            data-testid="new-org-slug"
            mono
            className="w-full"
            value={effectiveSlug}
            placeholder="acme"
            onChange={(e) => {
              setSlugTouched(true);
              setSlug(e.target.value.toLowerCase());
            }}
          />
        </Field>
        {create.error && <p className="text-sm text-deny">{errorMessage(create.error)}</p>}
        <button type="submit" hidden />
      </form>
    </Dialog>
  );
}

export function errorMessage(err: unknown): string {
  if (err && typeof err === "object" && "message" in err) return String((err as { message: unknown }).message);
  return String(err);
}

function UserFooter({ collapsed }: { collapsed: boolean }) {
  const { api, identityId, signOut } = useSession();
  const [theme, setTheme] = useState<Theme>(initialTheme);
  useEffect(() => {
    const onTheme = (e: Event) => setTheme((e as CustomEvent<Theme>).detail);
    window.addEventListener("varlatch:theme", onTheme);
    return () => window.removeEventListener("varlatch:theme", onTheme);
  }, []);
  const profile = useQuery({ queryKey: ["me-profile"], queryFn: () => api.getMyProfile(), retry: false, staleTime: 60_000 });
  const name = profile.data?.name || (identityId ? `${identityId.slice(0, 12)}…` : "…");
  const toggleTheme = (
    <button
      type="button"
      aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
      title={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
      onClick={() => applyTheme(theme === "dark" ? "light" : "dark")}
      className="flex size-8 cursor-pointer items-center justify-center rounded-md border border-bd text-muted hover:bg-hover hover:text-fg"
    >
      {theme === "dark" ? <Sun size={15} /> : <Moon size={15} />}
    </button>
  );
  const signOutButton = (
    <button
      type="button"
      aria-label="Sign out"
      title="Sign out"
      data-testid="sign-out"
      onClick={() => void signOut()}
      className="flex size-8 cursor-pointer items-center justify-center rounded-md border border-bd text-muted hover:bg-deny/10 hover:text-deny"
    >
      <LogOut size={15} />
    </button>
  );
  return (
    <div className={cn("border-t border-bd py-3", collapsed ? "space-y-2 px-2" : "px-3")}>
      <div className={cn("flex items-center", collapsed ? "flex-col gap-2" : "gap-2")}>
        <NavLink
          to="/account"
          data-testid="nav-profile"
          title={collapsed ? `${name} (account)` : "Account settings"}
          className={({ isActive }) =>
            cn(
              "flex min-w-0 flex-1 items-center gap-2.5 rounded-lg p-1.5 transition-colors hover:bg-hover",
              isActive && "bg-hover",
              collapsed && "justify-center",
            )
          }
        >
          <Avatar name={profile.data?.name ?? identityId ?? "?"} image={profile.data?.image ?? null} size="md" />
          {collapsed && (
            <span className="sr-only" data-testid="whoami" title={`Signed in as ${identityId ?? ""}`}>
              {name}
            </span>
          )}
          {!collapsed && (
            <span className="min-w-0">
              <span className="block truncate text-[13px] font-medium text-fg" data-testid="whoami" title={`Signed in as ${identityId ?? ""}`}>
                {name}
              </span>
              <span className="block truncate text-xs text-muted">{displayEmail(profile.data?.email) ?? "Account settings"}</span>
            </span>
          )}
        </NavLink>
        {toggleTheme}
        {signOutButton}
      </div>
    </div>
  );
}
