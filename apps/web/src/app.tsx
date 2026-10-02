// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { lazy, Suspense, useEffect, useMemo } from "react";
import { createBrowserRouter, Navigate, Outlet, RouterProvider } from "react-router-dom";
import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import { ConvexReactClient, ConvexProviderWithAuth } from "convex/react";
import { LiveUpdatesStatus } from "./components/LiveUpdatesStatus";
import { SessionProvider, useSession } from "./lib/session";
import { showPreferredTheme } from "./lib/theme";
import { DialogProvider } from "./components/Dialog";
import { ToastProvider } from "./components/Toast";
import { Shell, lastOrg } from "./shell/Shell";
import {
  FullPageLoading,
  MaintenanceBanner,
  MaintenanceScreen,
  SignInScreen,
  WelcomeScreen,
} from "./shell/AuthScreens";

const ProjectsPage = lazy(() => import("./features/projects/ProjectsPage").then((m) => ({ default: m.ProjectsPage })));
const ProjectLayout = lazy(() => import("./features/projects/ProjectLayout").then((m) => ({ default: m.ProjectLayout })));
const ProjectValues = lazy(() => import("./features/projects/MatrixPage").then((m) => ({ default: m.MatrixPage })));
const ContractPage = lazy(() => import("./features/projects/ContractPage").then((m) => ({ default: m.ContractPage })));
const ProjectActivity = lazy(() => import("./features/projects/ProjectActivity").then((m) => ({ default: m.ProjectActivity })));
const ProjectIntegrations = lazy(() =>
  import("./features/projects/ProjectIntegrations").then((m) => ({ default: m.ProjectIntegrations })),
);
const EnvironmentLayout = lazy(() =>
  import("./features/environments/EnvironmentLayout").then((m) => ({ default: m.EnvironmentLayout })),
);
const EditorPage = lazy(() => import("./features/environments/EditorPage").then((m) => ({ default: m.EditorPage })));
const EnvironmentActivity = lazy(() =>
  import("./features/environments/EnvironmentActivity").then((m) => ({ default: m.EnvironmentActivity })),
);
const IntegrationsPage = lazy(() => import("./features/sync/IntegrationsPage").then((m) => ({ default: m.IntegrationsPage })));
const AccessPage = lazy(() => import("./features/access/AccessPage").then((m) => ({ default: m.AccessPage })));
const ConnectionsPage = lazy(() => import("./features/sync/ConnectionsPage").then((m) => ({ default: m.ConnectionsPage })));
const AuditPage = lazy(() => import("./features/audit/AuditPage").then((m) => ({ default: m.AuditPage })));
const SettingsPage = lazy(() => import("./features/settings/SettingsPage").then((m) => ({ default: m.SettingsPage })));
const AccountLayout = lazy(() => import("./features/account/AccountLayout").then((m) => ({ default: m.AccountLayout })));
const ProfilePage = lazy(() => import("./features/settings/ProfilePage").then((m) => ({ default: m.ProfilePage })));
const SecurityPage = lazy(() => import("./features/account/SecurityPage").then((m) => ({ default: m.SecurityPage })));
const SessionsPage = lazy(() => import("./features/account/SessionsPage").then((m) => ({ default: m.SessionsPage })));
const InstallationPage = lazy(() =>
  import("./features/installation/InstallationPage").then((m) => ({ default: m.InstallationPage })),
);

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

/** Route-preserving auth gate (design R2 §Q4). */
function AuthGate({ children }: { children: React.ReactNode }) {
  const { needsAuth, identityId, maintenance } = useSession();
  // Maintenance is never "signed out" (ADR-0036 D6): the session exchange
  // retries by itself and the page continues where it was.
  if (maintenance && !identityId) return <MaintenanceScreen />;
  if (needsAuth) return <SignInScreen />;
  return (
    <React.Fragment key={identityId}>
      {maintenance && <MaintenanceBanner />}
      {children}
    </React.Fragment>
  );
}

/** "/" lands in the last organization visited, else the first one. */
function OrgIndexRedirect() {
  const { api } = useSession();
  const orgs = useQuery({ queryKey: ["orgs"], queryFn: () => api.listOrganizations() });
  if (!orgs.data) return <FullPageLoading />;
  const remembered = lastOrg();
  const target = orgs.data.items.find((o) => o.slug === remembered) ?? orgs.data.items[0];
  if (!target) return <WelcomeScreen />;
  return <Navigate to={`/o/${target.slug}/projects`} replace />;
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

function Lazy() {
  return (
    <Suspense fallback={<FullPageLoading />}>
      <Outlet />
    </Suspense>
  );
}

const router = createBrowserRouter([
  { path: "/", element: <OrgIndexRedirect /> },
  // Old locations of the account pages.
  { path: "/credentials", element: <Navigate to="/account/sessions" replace /> },
  { path: "/profile", element: <Navigate to="/account" replace /> },
  {
    element: <Shell />,
    children: [
      {
        element: <Lazy />,
        children: [
          {
            path: "/account",
            element: <AccountLayout />,
            children: [
              { index: true, element: <ProfilePage /> },
              { path: "security", element: <SecurityPage /> },
              { path: "sessions", element: <SessionsPage /> },
            ],
          },
          { path: "/installation/settings", element: <InstallationPage /> },
        ],
      },
    ],
  },
  {
    path: "/o/:org",
    element: <Shell />,
    children: [
      {
        element: <Lazy />,
        children: [
          { index: true, element: <Navigate to="projects" replace /> },
          { path: "projects", element: <ProjectsPage /> },
          {
            path: "p/:project",
            element: <ProjectLayout />,
            children: [
              { index: true, element: <ProjectValues /> },
              { path: "contract", element: <ContractPage /> },
              { path: "integrations", element: <ProjectIntegrations /> },
              { path: "activity", element: <ProjectActivity /> },
            ],
          },
          {
            path: "p/:project/e/:env",
            element: <EnvironmentLayout />,
            children: [
              { index: true, element: <EditorPage /> },
              { path: "integrations", element: <IntegrationsPage /> },
              { path: "activity", element: <EnvironmentActivity /> },
            ],
          },
          { path: "access", element: <AccessPage /> },
          { path: "connections", element: <ConnectionsPage /> },
          { path: "audit", element: <AuditPage /> },
          { path: "settings", element: <SettingsPage /> },
        ],
      },
    ],
  },
]);

export function App() {
  useEffect(() => showPreferredTheme(), []);
  return (
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <DialogProvider>
          <SessionProvider>
            <AuthGate>
              <ConvexWithSession>
                <RouterProvider router={router} />
              </ConvexWithSession>
            </AuthGate>
          </SessionProvider>
        </DialogProvider>
      </ToastProvider>
    </QueryClientProvider>
  );
}
