// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { lazy, Suspense, useEffect, useMemo, useState } from "react";
import {
  createBrowserRouter,
  Link,
  Navigate,
  NavLink,
  Outlet,
  RouterProvider,
  useNavigate,
  useParams,
} from "react-router-dom";
import { QueryClient, QueryClientProvider, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ConvexReactClient, ConvexProviderWithAuth } from "convex/react";
import { LiveUpdatesStatus } from "./components/LiveUpdatesStatus";
import { FolderKey, LogOut, Moon, Plug, ScrollText, Search, Settings2, Sun, Users } from "lucide-react";
import { SessionProvider, useSession } from "./lib/session";
import { applyTheme, initialTheme } from "./lib/theme";
import { Avatar, Button, Card, Input, Select, cn } from "./components/ui";
import { ProfilePage } from "./features/settings/ProfilePage";
const ProjectsPage = lazy(() => import("./features/projects/ProjectsPage").then(m => ({ default: m.ProjectsPage })));
const AuditPage = lazy(() => import("./features/audit/AuditPage").then(m => ({ default: m.AuditPage })));
const AccessPage = lazy(() => import("./features/access/AccessPage").then(m => ({ default: m.AccessPage })));
const CredentialsPage = lazy(() => import("./features/access/CredentialsPage").then(m => ({ default: m.CredentialsPage })));
const ContractPage = lazy(() => import("./features/projects/ContractPage").then(m => ({ default: m.ContractPage })));
const SettingsPage = lazy(() => import("./features/settings/SettingsPage").then(m => ({ default: m.SettingsPage })));
import { CommandPalette, isMacPlatform } from "./components/CommandPalette";
const MatrixPage = lazy(() => import("./features/projects/MatrixPage").then(m => ({ default: m.MatrixPage })));
const EditorPage = lazy(() => import("./features/environments/EditorPage").then(m => ({ default: m.EditorPage })));
const IntegrationsPage = lazy(() => import("./features/sync/IntegrationsPage").then(m => ({ default: m.IntegrationsPage })));
const ConnectionsPage = lazy(() => import("./features/sync/ConnectionsPage").then(m => ({ default: m.ConnectionsPage })));

const CONVEX_URL =
  // Runtime config first (prebuilt release images set it via the container
  // entrypoint), then the Vite dev/build-time env. `||` not `??`: unset
  // values arrive as "" and must fall back.
  (window as { __VARLATCH__?: { convexUrl?: string } }).__VARLATCH__?.convexUrl ||
  (import.meta as { env?: Record<string, string> }).env?.VITE_CONVEX_URL ||
  "http://localhost:3210";
const convex = new ConvexReactClient(CONVEX_URL);

// Secrets never enter this cache: disclosures are imperative mutations only.
const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: 1, staleTime: 15_000 } },
});

function BrandMark({ size = 24 }: { size?: number }) {
  return (
    <img
      src="/brand/varlatch-app-icon.png"
      width={size}
      height={size}
      alt=""
      className="brand-mark"
    />
  );
}

function SignInScreen() {
  const { signInWithPasskey } = useSession();
  const [status, setStatus] = useState("");
  return (
    <main className="min-h-screen grid place-items-center">
      <Card className="w-96 text-center space-y-4 py-8">
        <BrandMark size={56} />
        <h1 className="text-xl font-semibold">Varlatch</h1>
        <p className="text-muted text-sm">Self-host-first secrets and configuration.</p>
        <Button
          onClick={() => {
            setStatus("Waiting for your authenticator…");
            signInWithPasskey().catch((err) =>
              setStatus(`Sign-in failed: ${err instanceof Error ? err.message : String(err)}`),
            );
          }}
        >
          Sign in with passkey
        </Button>
        <p id="signin-status" className="text-sm text-muted min-h-5">{status}</p>
      </Card>
    </main>
  );
}

/** Route-preserving auth gate (design R2 §Q4). */
function AuthGate({ children }: { children: React.ReactNode }) {
  const { needsAuth, identityId, maintenance } = useSession();
  // Maintenance is never "signed out" (ADR-0036 D6): the session exchange
  // retries by itself and the page continues where it was.
  if (maintenance && !identityId) return <MaintenanceScreen />;
  if (needsAuth) return <SignInScreen />;
  return (
    <React.Fragment key={identityId}>
      {maintenance && (
        <div
          role="status"
          aria-live="polite"
          data-testid="maintenance-status"
          className="fixed top-3 left-1/2 -translate-x-1/2 z-50 flex items-center gap-2 rounded-full border border-bd bg-raised px-3 py-1.5 text-xs text-muted shadow-sm"
        >
          <span className="size-2 rounded-full bg-muted animate-pulse" aria-hidden="true" />
          Installation maintenance · requests resume automatically
        </div>
      )}
      {children}
    </React.Fragment>
  );
}

function MaintenanceScreen() {
  return (
    <main className="min-h-screen flex items-center justify-center p-6" data-testid="maintenance-screen">
      <Card className="max-w-md w-full">
        <div className="flex items-center gap-3 mb-2">
          <span className="size-2.5 rounded-full bg-muted animate-pulse" aria-hidden="true" />
          <h1 className="font-semibold">Varlatch is under maintenance</h1>
        </div>
        <p className="text-sm text-muted">
          A restore or an upgrade is in progress. This page reconnects by itself — there is no need to sign in again.
        </p>
      </Card>
    </main>
  );
}

function OrgIndexRedirect() {
  const { api } = useSession();
  const orgs = useQuery({ queryKey: ["orgs"], queryFn: () => api.listOrganizations() });
  if (!orgs.data) return <p className="p-8 text-muted">Loading…</p>;
  const first = orgs.data.items[0];
  if (!first) return <CreateFirstOrg />;
  return <Navigate to={`/o/${first.slug}/projects`} replace />;
}

function InstallationSettingsLink() {
  const { api } = useSession();
  const access = useQuery({ queryKey: ["installation-backups"], queryFn: () => api.getInstallationBackups(), retry: false });
  return access.data ? <Link className="text-sm text-muted hover:text-fg" to="/installation/settings">Installation settings</Link> : null;
}

function CreateFirstOrg() {
  const { api, identityId } = useSession();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [slug, setSlug] = useState("");
  const create = useMutation({
    mutationFn: () => api.createOrganization({ slug, name: slug }),
    onSuccess: async (org) => {
      await qc.invalidateQueries({ queryKey: ["orgs"] });
      navigate(`/o/${org.slug}/projects`);
    },
  });
  return (
    <main className="min-h-screen grid place-items-center">
      <Card className="w-[26rem] space-y-4 py-8">
        <BrandMark size={48} />
        <h1 className="text-xl font-semibold">Welcome to Varlatch</h1>
        <p className="text-sm text-muted" data-testid="whoami">Signed in as {identityId}</p>
        <p className="text-sm">Create your first organization to get started.</p>
        <InstallationSettingsLink />
        <div className="flex gap-2">
          <Input
            data-testid="new-org-slug"
            placeholder="organization-slug"
            value={slug}
            onChange={(e) => setSlug(e.target.value.toLowerCase())}
          />
          <Button data-testid="create-org" disabled={!slug || create.isPending} onClick={() => create.mutate()}>
            Create
          </Button>
        </div>
        {create.error && <p className="text-deny text-sm">{String(create.error)}</p>}
      </Card>
    </main>
  );
}

const NAV = [
  { to: "projects", label: "Projects", icon: FolderKey },
  { to: "access", label: "Access", icon: Users },
  { to: "connections", label: "Connections", icon: Plug },
  { to: "audit", label: "Audit", icon: ScrollText },
  { to: "settings", label: "Settings", icon: Settings2 },
];

/** Keycap-styled hint, e.g. ⌘K on macOS / Ctrl K elsewhere. */
function Keycap({ children }: { children: React.ReactNode }) {
  return (
    <kbd className="rounded border border-bd bg-inset px-1 py-px font-mono text-[10px] leading-none text-muted">
      {children}
    </kbd>
  );
}

function Shell() {
  const { org } = useParams();
  const { api, identityId, signOut } = useSession();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const orgs = useQuery({ queryKey: ["orgs"], queryFn: () => api.listOrganizations() });
  const [theme, setTheme] = useState<"dark" | "light">(initialTheme);
  useEffect(() => applyTheme(theme), [theme]);
  // Settings → Appearance changes the theme too; keep the footer toggle honest.
  useEffect(() => {
    const onTheme = (e: Event) => setTheme((e as CustomEvent<"dark" | "light">).detail);
    window.addEventListener("varlatch:theme", onTheme);
    return () => window.removeEventListener("varlatch:theme", onTheme);
  }, []);
  const profile = useQuery({
    queryKey: ["me-profile"],
    queryFn: () => api.getMyProfile(),
    retry: false,
    staleTime: 60_000,
  });
  const [creatingOrg, setCreatingOrg] = useState(false);
  const [newOrgSlug, setNewOrgSlug] = useState("");
  const createOrg = useMutation({
    mutationFn: () => api.createOrganization({ slug: newOrgSlug, name: newOrgSlug }),
    onSuccess: async (created) => {
      setCreatingOrg(false);
      setNewOrgSlug("");
      await qc.invalidateQueries({ queryKey: ["orgs"] });
      navigate(`/o/${created.slug}/projects`);
    },
  });

  return (
    <div className="min-h-screen flex">
      {/* Sticky viewport-height sidebar: the page container is min-h-screen, so
          without this the aside stretches to full document height and the
          footer (My credentials / sign out) lands below the fold on long pages. */}
      <aside className="w-60 shrink-0 border-r border-bd bg-raised flex flex-col sticky top-0 h-screen">
        <div className="p-3 border-b border-bd">
          <Link
            to={org ? `/o/${org}/projects` : "/"}
            className="flex items-center gap-2 mb-2 rounded hover:opacity-80"
            aria-label="Varlatch home"
          >
            <BrandMark size={22} />
            <span className="font-semibold">Varlatch</span>
          </Link>
          {/* Spacious org switcher (design R1): switching navigates; the
              trailing option opens the inline create form below. */}
          <Select
            data-testid="org-switcher"
            aria-label="Switch organization"
            className="w-full"
            buttonClassName="py-2"
            value={creatingOrg ? "__create__" : org}
            onChange={(v) => {
              if (v === "__create__") setCreatingOrg(true);
              else {
                setCreatingOrg(false);
                navigate(`/o/${v}/projects`);
              }
            }}
            options={[
              ...(orgs.data?.items.map((o) => ({ value: o.slug, label: o.name })) ?? []),
              { value: "__create__", label: "＋ New organization…" },
            ]}
          />
          {creatingOrg && (
            <form
              className="mt-2 space-y-2"
              onSubmit={(e) => {
                e.preventDefault();
                if (newOrgSlug) createOrg.mutate();
              }}
            >
              <Input
                autoFocus
                data-testid="new-org-slug"
                className="w-full"
                placeholder="organization-slug"
                value={newOrgSlug}
                onChange={(e) => setNewOrgSlug(e.target.value.toLowerCase())}
                onKeyDown={(e) => {
                  if (e.key === "Escape") setCreatingOrg(false);
                }}
              />
              <div className="flex gap-2">
                <Button
                  type="submit"
                  data-testid="create-org"
                  className="flex-1"
                  disabled={!newOrgSlug || createOrg.isPending}
                >
                  Create
                </Button>
                <Button type="button" variant="ghost" onClick={() => setCreatingOrg(false)}>
                  Cancel
                </Button>
              </div>
              {createOrg.error && (
                <p className="text-deny text-xs">{String(createOrg.error)}</p>
              )}
            </form>
          )}
        </div>
        <nav className="p-2 space-y-0.5 flex-1 overflow-y-auto">
          <button
            type="button"
            data-testid="nav-search"
            onClick={() => window.dispatchEvent(new CustomEvent("varlatch:open-palette"))}
            className="mb-1.5 flex w-full cursor-pointer items-center gap-2.5 rounded-md border border-bd bg-inset px-2.5 py-1.5 text-sm text-muted hover:text-fg"
          >
            <Search size={15} />
            <span className="flex-1 text-left">Search</span>
            <Keycap>{isMacPlatform() ? "⌘K" : "Ctrl K"}</Keycap>
          </button>
          {NAV.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={`/o/${org}/${to}`}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm no-underline",
                  isActive ? "bg-accent-dim text-fg" : "text-muted hover:text-fg hover:bg-inset",
                )
              }
            >
              <Icon size={15} />
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="p-3 border-t border-bd space-y-2">
          {/* Machines (profile 404) fall back to the raw identity id and keep
              the /profile link hidden — nothing there for them to edit. */}
          {(() => {
            const displayName =
              profile.data?.name ||
              (identityId ? `${identityId.slice(0, 14)}…` : "…");
            const inner = (
              <>
                <Avatar name={profile.data?.name ?? identityId ?? "?"} image={profile.data?.image ?? null} size="sm" />
                <span className="min-w-0">
                  <span
                    className="block truncate text-sm text-fg"
                    data-testid="whoami"
                    title={`Signed in as ${identityId ?? ""}`}
                  >
                    {displayName}
                  </span>
                  {profile.data?.email && (
                    <span className="block truncate text-xs text-muted">{profile.data.email}</span>
                  )}
                </span>
              </>
            );
            return profile.isError ? (
              <div className="flex items-center gap-2">{inner}</div>
            ) : (
              <Link
                to="/profile"
                data-testid="nav-profile"
                className="flex items-center gap-2 rounded-md -mx-1 px-1 py-0.5 no-underline hover:bg-inset"
                title="Edit your profile"
              >
                {inner}
              </Link>
            );
          })()}
          <div className="flex items-center gap-3">
            <Link to="/credentials" className="text-xs text-muted hover:text-fg no-underline">
              My credentials
            </Link>
            <span className="flex-1" />
            <button
              className="text-xs text-muted hover:text-fg cursor-pointer inline-flex items-center gap-1"
              aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
              title={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
              onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
            >
              {theme === "dark" ? <Sun size={13} /> : <Moon size={13} />}
            </button>
            <button
              className="text-xs text-muted hover:text-deny cursor-pointer inline-flex items-center gap-1"
              onClick={() => void signOut()}
            >
              <LogOut size={11} /> Sign out
            </button>
          </div>
        </div>
      </aside>
      <main className="flex-1 p-6 max-w-5xl">
        <div className="mb-3"><InstallationSettingsLink /></div>
        <Outlet />
      </main>
      <CommandPalette />
    </div>
  );
}

function ConvexWithSession({ children }: { children: React.ReactNode }) {
  const { identityId, mintConvexToken } = useSession();
  const auth = useMemo(
    () => ({
      isLoading: false,
      isAuthenticated: identityId !== null,
      fetchAccessToken: async () => mintConvexToken(),
    }),
    [identityId, mintConvexToken],
  );
  return (
    <ConvexProviderWithAuth client={convex} useAuth={() => auth}>
      <LiveUpdatesStatus />
      {children}
    </ConvexProviderWithAuth>
  );
}

const router = createBrowserRouter([
  { path: "/", element: <OrgIndexRedirect /> },
  { path: "/credentials", element: <main className="p-6 max-w-3xl mx-auto"><CredentialsPage /></main> },
  { path: "/profile", element: <ProfilePage /> },
  { path: "/installation/settings", element: <main className="p-6 max-w-5xl mx-auto"><Link to="/">Back to organizations</Link><SettingsPage /></main> },
  {
    path: "/o/:org",
    element: <Shell />,
    children: [
      { index: true, element: <Navigate to="projects" replace /> },
      { path: "projects", element: <ProjectsPage /> },
      { path: "p/:project", element: <MatrixPage /> },
      { path: "p/:project/e/:env", element: <EditorPage /> },
      { path: "p/:project/e/:env/integrations", element: <IntegrationsPage /> },
      { path: "p/:project/contract", element: <ContractPage /> },
      { path: "access", element: <AccessPage /> },
      { path: "connections", element: <ConnectionsPage /> },
      { path: "audit", element: <AuditPage /> },
      { path: "settings", element: <SettingsPage /> },
    ],
  },
]);

export function App() {
  useEffect(() => applyTheme(initialTheme()), []);
  return (
    <QueryClientProvider client={queryClient}>
      <SessionProvider>
        <AuthGate>
          <ConvexWithSession>
            <Suspense fallback={<p className="p-8 text-muted">Loading…</p>}><RouterProvider router={router} /></Suspense>
          </ConvexWithSession>
        </AuthGate>
      </SessionProvider>
    </QueryClientProvider>
  );
}
