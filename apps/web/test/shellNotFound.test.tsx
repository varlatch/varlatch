// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestInstance, type ReactTestRenderer } from "react-test-renderer";
import { createMemoryRouter, RouterProvider } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * The shell itself around an address without a page, in an Organization
 * frozen for an incident: the freeze banner stays, and so does the
 * not-found page. A page that cannot work while frozen still gives way.
 */

const fake = vi.hoisted(() => ({ frozen: true }));
vi.hoisted(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const nothing = { addEventListener: () => {}, removeEventListener: () => {} };
  vi.stubGlobal("window", { ...nothing, scrollTo: () => {}, dispatchEvent: () => true, setInterval: () => 0, clearInterval: () => {} });
  vi.stubGlobal("document", { title: "Varlatch", documentElement: { dataset: {}, classList: { contains: () => false, toggle: () => {} } }, ...nothing });
  vi.stubGlobal("localStorage", { getItem: () => null, setItem: () => {}, removeItem: () => {} });
  vi.stubGlobal("matchMedia", () => ({ matches: false, ...nothing }));
});
const FREEZE = { id: "ofz_1", frozenAt: "2026-11-11T10:00:00.000Z", frozenBy: { id: "idn_ada", name: "Ada" }, reason: "A CI token leaked", liftedAt: null, liftedBy: null, liftMethod: null };
vi.mock("../src/lib/session", () => ({
  useSession: () => ({
    identityId: "idn_ada",
    signOut: () => {},
    api: {
      listOrganizations: async () => ({ items: [{ id: "org_a", slug: "acme", name: "Acme", role: "member" }] }),
      incidentFreeze: async () => ({ freeze: fake.frozen ? FREEZE : null, resumingTargets: null }),
      meta: async () => ({ capabilities: ["organizations.incident-freeze"] }),
      getMyProfile: async () => ({ name: "Ada" }),
    },
  }),
}));
vi.mock("../src/lib/membership", () => ({ useMembershipWatcher: () => {} }));
vi.mock("../src/lib/hotkeys", () => ({ useHotkeys: () => {}, modKey: () => "Ctrl" }));
vi.mock("../src/lib/theme", () => ({ applyTheme: () => {}, initialTheme: () => "dark" }));
vi.mock("../src/components/CommandPalette", () => ({ CommandPalette: () => null }));
vi.mock("../src/shell/ShortcutsDialog", () => ({ ShortcutsDialog: () => null }));
vi.mock("../src/components/Dialog", () => ({ Dialog: () => null, useConfirm: () => async () => true }));
vi.mock("../src/components/Toast", () => ({ useToast: () => ({ success: () => {}, error: () => {} }) }));
vi.mock("../src/features/settings/OrganizationDeletion", () => ({ DeletionBanner: () => null }));
vi.mock("../src/features/installation/releaseNotice", () => ({ NewerReleaseDot: () => null, RELEASE_TAB_PATH: "/", useInstallationRelease: () => ({ data: undefined }) }));

import { Shell } from "../src/shell/Shell";
import { NotFoundPage } from "../src/shell/RouteScreens";
import { NOT_FOUND } from "../src/shell/notFound";

let root: ReactTestRenderer;
beforeEach(() => {
  fake.frozen = true;
});
afterEach(async () => {
  await act(async () => root?.unmount());
});
async function open(path: string) {
  const router = createMemoryRouter(
    [{ path: "/o/:org", element: <Shell />, children: [{ path: "projects", element: <p data-testid="page">page</p> }, { path: "*", element: <NotFoundPage />, handle: NOT_FOUND }] }],
    { initialEntries: [path] },
  );
  await act(async () => {
    root = create(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <RouterProvider router={router} />
      </QueryClientProvider>,
    );
  });
  for (let i = 0; i < 6; i++) await act(async () => new Promise((resolve) => setTimeout(resolve, 0)));
}
const all = (id: string) => root.root.findAll((n) => typeof n.type === "string" && n.props["data-testid"] === id);
const text = (node: ReactTestInstance | string): string =>
  typeof node === "string" ? node : node.children.map((c) => text(c as ReactTestInstance | string)).join("");

describe("the shell of a frozen Organization", () => {
  it("shows the not-found page under the banner", async () => {
    await open("/o/acme/nope");
    expect(text(all("incident-freeze-banner")[0]!)).toContain("This organization is frozen for an incident");
    expect(text(all("not-found")[0]!)).toContain("Page not found");
    // Its navigation too.
    expect(root.root.findAllByType("nav")).toHaveLength(1);
  });

  it("still shows the banner alone where a page cannot work", async () => {
    await open("/o/acme/projects");
    expect(all("incident-freeze-banner")).toHaveLength(1);
    expect(all("page")).toHaveLength(0);
    expect(all("not-found")).toHaveLength(0);
  });

  it("has no banner once it is not frozen", async () => {
    fake.frozen = false;
    await open("/o/acme/nope");
    expect(all("incident-freeze-banner")).toHaveLength(0);
    expect(all("not-found")).toHaveLength(1);
  });
});
