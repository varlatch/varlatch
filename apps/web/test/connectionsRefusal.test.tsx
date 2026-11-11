// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestInstance, type ReactTestRenderer } from "react-test-renderer";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { QueryClient, QueryClientProvider, type QueryKey } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { PlatformConnection, RefusedDestinations } from "@varlatch/protocol";

/**
 * The Connections page and this installation's refusals (ADR-0057 Decision
 * 8): a Connection the policy refuses says so, and once the host operator
 * allows it and varlatchd restarts, the warning goes away on the open page,
 * on the next sync change or the page's periodic check, without a reload.
 */

const fake = vi.hoisted(() => ({
  api: {} as Record<string, (...args: never[]) => unknown>,
  realtimeKeys: [] as unknown[][],
  capabilities: ["sync.targets", "security.refused-destinations", "organizations.permissions"],
}));
vi.hoisted(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const g = globalThis;
  vi.stubGlobal("window", {
    setInterval: g.setInterval.bind(g),
    clearInterval: g.clearInterval.bind(g),
    setTimeout: g.setTimeout.bind(g),
    clearTimeout: g.clearTimeout.bind(g),
  });
});
vi.mock("../src/lib/session", () => ({ useSession: () => ({ api: fake.api }) }));
// The page's realtime subscription: record the keys a "sync" change invalidates.
vi.mock("../src/lib/realtime", () => ({
  useOrgRealtime: (_org: string, _domains: string[], keys: unknown[][]) => {
    fake.realtimeKeys = keys;
  },
}));
vi.mock("../src/components/Toast", () => ({ useToast: () => ({ success: () => {}, error: () => {} }) }));
vi.mock("../src/components/Dialog", () => ({ Dialog: () => null, useConfirm: () => async () => false }));
vi.mock("../src/features/sync/useOrgEnvironments", () => ({ useOrgEnvironments: () => ({ byId: new Map(), loading: false }) }));
vi.mock("../src/features/projects/hooks", () => ({
  useOrgName: () => "Acme",
  useMeta: () => ({ data: { apiMajor: 1, capabilities: fake.capabilities, syncAdapters: ["coolify"] } }),
  useCapability: (c: string) => fake.capabilities.includes(c),
  keys: { orgSyncTargets: (org: string) => ["org-sync-targets", org] },
}));

import { ConnectionsPage } from "../src/features/sync/ConnectionsPage";
import { REFUSED_REFETCH_MS } from "../src/features/security-controls/RefusedDestinationsCard";
import { refusedDestinationsKey } from "../src/features/security-controls/keys";

const COOLIFY: PlatformConnection = {
  id: "pcn_1",
  organizationId: "org_1",
  platform: "coolify",
  baseIdentity: "https://coolify.lan:8443",
  name: "Coolify",
  createdAt: "2026-11-01T00:00:00Z",
  version: 1,
  updatedAt: null,
};
const REFUSED: RefusedDestinations = {
  generatedAt: "2026-11-11T12:00:00.000Z",
  sinceDays: 30,
  checked: 1,
  unresolved: 0,
  items: [{ kind: "coolify", id: "pcn_1", name: "Coolify", scheme: "https", host: "coolify.lan", port: 8443, reason: "private_address", since: null }],
};
const ALLOWED: RefusedDestinations = { ...REFUSED, items: [] };

let current: RefusedDestinations;
let actions: string[];
let root: ReactTestRenderer;
let client: QueryClient;

beforeEach(() => {
  current = REFUSED;
  actions = ["organization.read", "organization.manage"];
  fake.realtimeKeys = [];
  fake.api = {
    listPlatformConnections: async () => ({ items: [COOLIFY], nextCursor: null }),
    listOrgSyncTargets: async () => ({ items: [], nextCursor: null }),
    myOrganizationPermissions: async () => ({ organizationId: "org_1", role: "admin", actions }),
    refusedDestinations: vi.fn(async () => current),
  };
});
afterEach(async () => {
  await act(async () => root?.unmount());
});

const settle = async () => {
  for (let i = 0; i < 10; i++) await act(async () => new Promise((resolve) => globalThis.setTimeout(resolve, 0)));
};
const all = (id: string) => root.root.findAll((n) => typeof n.type === "string" && n.props["data-testid"] === id);
const text = (node: ReactTestInstance | string): string =>
  typeof node === "string" ? node : node.children.map((c) => text(c as ReactTestInstance | string)).join("");

async function mount() {
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
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
  await settle();
}

/** What a realtime "sync" change does on this page: invalidate the keys it subscribed. */
async function syncChanged() {
  await act(async () => {
    for (const key of fake.realtimeKeys) await client.invalidateQueries({ queryKey: key as QueryKey });
  });
  await settle();
}

describe("a Connection this installation refuses", () => {
  it("shows the refusal on a Connection no integration uses, and drops it once the host allows it", async () => {
    await mount();
    expect(all("connection-refused-pcn_1")).toHaveLength(1);
    expect(text(all("connection-refused-pcn_1")[0]!)).toContain("Refused by this installation");
    expect(text(all("connection-refused-pcn_1")[0]!)).toContain("This address is on a private network");

    // The operator allows it and restarts varlatchd; the next sync change refreshes the page.
    current = ALLOWED;
    expect(fake.realtimeKeys).toContainEqual([...refusedDestinationsKey("acme")]);
    await syncChanged();
    expect(all("connection-refused-pcn_1")).toHaveLength(0);
  });

  it("is also asked again periodically, less often than the server reuses a check", async () => {
    await mount();
    const query = client.getQueryCache().find({ queryKey: refusedDestinationsKey("acme") });
    expect(query).toBeDefined();
    expect((query!.options as { refetchInterval?: unknown }).refetchInterval).toBe(REFUSED_REFETCH_MS);
    expect(REFUSED_REFETCH_MS).toBeGreaterThan(30_000);
    expect((query!.options as { refetchIntervalInBackground?: unknown }).refetchIntervalInBackground).toBe(false);
    // A refetch with the destination allowed clears the warning.
    current = ALLOWED;
    await act(async () => {
      await query!.fetch();
    });
    await settle();
    expect(all("connection-refused-pcn_1")).toHaveLength(0);
  });

  it("is not asked for without organization.manage", async () => {
    actions = ["organization.read"];
    await mount();
    expect(fake.api.refusedDestinations).not.toHaveBeenCalled();
    expect(all("connection-refused-pcn_1")).toHaveLength(0);
  });
});
