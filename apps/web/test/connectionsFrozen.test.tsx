// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestRenderer } from "react-test-renderer";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { IncidentFreeze } from "@varlatch/sdk";

/**
 * The Connections page while the organization is frozen for an incident
 * (ADR-0055; review of #109): it stays, with the lists and revocation, and
 * leaves out what the freeze refuses: the GitHub App, new connections and
 * credential changes.
 */

const fake = vi.hoisted(() => ({ api: {} as Record<string, (...args: never[]) => unknown> }));
vi.hoisted(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  vi.stubGlobal("window", { setInterval: globalThis.setInterval.bind(globalThis), clearInterval: globalThis.clearInterval.bind(globalThis) });
});
vi.mock("../src/lib/session", () => ({ useSession: () => ({ api: fake.api }) }));
vi.mock("../src/lib/realtime", () => ({ useOrgRealtime: () => undefined }));
vi.mock("../src/shell/Shell", () => ({ errorMessage: (err: unknown) => String(err) }));
vi.mock("../src/components/Toast", () => ({ useToast: () => ({ success: () => {}, error: () => {} }) }));
vi.mock("../src/components/Dialog", () => ({ Dialog: () => null, useConfirm: () => async () => false }));
vi.mock("../src/components/PageHeader", () => ({
  PageHeader: ({ actions }: { actions?: React.ReactNode }) => <header data-testid="page-header">{actions}</header>,
}));
vi.mock("../src/features/projects/hooks", () => ({
  useOrgName: () => "Acme",
  useMeta: () => ({ data: { capabilities: ["sync.targets", "organizations.incident-freeze"], syncAdapters: ["github-actions", "coolify"] } }),
  useCapability: () => true,
  keys: { orgSyncTargets: (org: string) => ["org-sync-targets", org] },
}));
vi.mock("../src/features/sync/useOrgEnvironments", () => ({ useOrgEnvironments: () => ({ byId: new Map() }) }));
vi.mock("../src/features/sync/GitHubApp", () => ({ GitHubAppPanel: () => <div data-testid="github-app-panel" /> }));

import { ConnectionsPage } from "../src/features/sync/ConnectionsPage";

const FREEZE: IncidentFreeze = {
  id: "ofz_1",
  frozenAt: "2026-11-11T10:00:00.000Z",
  frozenBy: { id: "idn_ada", name: "Ada" },
  reason: "A CI token leaked",
  liftedAt: null,
  liftedBy: null,
  liftMethod: null,
};
const CONNECTION = {
  id: "pcn_1",
  platform: "coolify",
  baseIdentity: "https://coolify.example.com",
  name: "prod coolify",
  credentialKind: "token",
  credentialExpiresAt: null,
  credentialExpirySeenAt: null,
  createdAt: "2026-11-01T00:00:00.000Z",
  updatedAt: null,
};

let root: ReactTestRenderer;
async function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => {
    root = create(
      <QueryClientProvider client={client}>
        <MemoryRouter initialEntries={["/o/acme/connections"]}>
          <Routes>
            <Route path="/o/:org/connections" element={<ConnectionsPage />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    );
  });
  for (let i = 0; i < 4; i++) await act(async () => new Promise((resolve) => globalThis.setTimeout(resolve, 0)));
}
const all = (id: string) => root.root.findAll((n) => n.props["data-testid"] === id);
const menuItems = () => (all(`connection-menu-${CONNECTION.id}`)[0]!.props.items as { "data-testid": string }[]).map((i) => i["data-testid"]);

let open: IncidentFreeze | null;
beforeEach(() => {
  open = null;
  fake.api = {
    incidentFreeze: async () => ({ freeze: open, resumingTargets: null, history: [] }),
    listPlatformConnections: async () => ({ items: [CONNECTION], nextCursor: null }),
    listOrgSyncTargets: async () => ({ items: [], nextCursor: null }),
  };
});

describe("the Connections page", () => {
  it("offers everything when not frozen", async () => {
    await mount();
    expect(all("connections-frozen")).toEqual([]);
    expect(all("github-app-panel")).toHaveLength(1);
    expect(all("new-connection").length).toBeGreaterThan(0);
    expect(menuItems()).toEqual([`replace-credential-${CONNECTION.id}`, `revoke-connection-${CONNECTION.id}`]);
  });

  it("while frozen, keeps the list and revocation, and leaves out the GitHub App, new connections and credential changes", async () => {
    open = FREEZE;
    await mount();
    expect(all("connections-frozen").length).toBeGreaterThan(0);
    expect(all("github-app-panel")).toEqual([]);
    expect(all("new-connection")).toEqual([]);
    expect(menuItems()).toEqual([`revoke-connection-${CONNECTION.id}`]);
  });
});
