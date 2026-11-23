// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestInstance, type ReactTestRenderer } from "react-test-renderer";
import { createMemoryRouter, matchRoutes, Outlet, RouterProvider, type RouteObject } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * The route table (src/app.tsx): an unknown address shows the app's own
 * page, in the shell; a page that fails shows a page of the app too, and
 * never what the error says. The router's own error page ("Unexpected
 * Application Error!") must not show anywhere.
 */

const SECRET = "postgres://db.internal: a detail of the failure";
const fake = vi.hoisted(() => ({ throwIn: "" }));
vi.hoisted(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  vi.stubGlobal("window", { __VARLATCH__: {}, location: { reload: vi.fn() } });
});
vi.mock("../src/lib/backend", () => ({ backend: () => ({ session: "varlatch", realtime: "sse" }) }));
vi.mock("../src/lib/session", () => ({ SessionProvider: ({ children }: { children: React.ReactNode }) => children, useSession: () => ({ api: {} }) }));
vi.mock("../src/lib/sseProvider", () => ({ SseProvider: ({ children }: { children: React.ReactNode }) => children }));
vi.mock("../src/lib/tailnetConnection", () => ({ TailnetConnectionProvider: ({ children }: { children: React.ReactNode }) => children }));
vi.mock("../src/components/LiveUpdatesStatus", () => ({ LiveUpdatesStatus: () => null, RealtimeUnavailable: () => null, SseLiveUpdatesStatus: () => null }));
vi.mock("../src/components/Dialog", () => ({ DialogProvider: ({ children }: { children: React.ReactNode }) => children }));
vi.mock("../src/components/Toast", () => ({ ToastProvider: ({ children }: { children: React.ReactNode }) => children }));
vi.mock("../src/features/security-controls/approval", () => ({ ApprovalDialogProvider: ({ children }: { children: React.ReactNode }) => children }));
vi.mock("../src/shell/AuthScreens", () => ({
  FullPageLoading: () => <p>loading</p>, MaintenanceBanner: () => null, PasskeyVerificationBanner: () => null, MaintenanceScreen: () => null, SignInScreen: () => null, WelcomeScreen: () => null,
}));
vi.mock("../src/shell/Shell", () => ({
  Shell: () => {
    if (fake.throwIn === "shell") throw new Error(SECRET);
    return (
      <div data-testid="shell">
        <Outlet />
      </div>
    );
  },
  lastOrg: () => null,
}));
const page = (name: string) => () => {
  if (fake.throwIn === name) throw new Error(SECRET);
  return <p data-testid={`page-${name}`}>{name}</p>;
};
vi.mock("../src/features/projects/ProjectsPage", () => ({ ProjectsPage: page("projects") }));
vi.mock("../src/features/device/DevicePage", () => ({ DevicePage: page("device") }));

let routes: RouteObject[];
beforeAll(async () => {
  ({ routes } = await import("../src/app"));
});

let root: ReactTestRenderer;
let logged: ReturnType<typeof vi.spyOn>;
beforeEach(() => {
  fake.throwIn = "";
  logged = vi.spyOn(console, "error").mockImplementation(() => {});
});
afterEach(async () => {
  await act(async () => root?.unmount());
  logged.mockRestore();
});
async function open(path: string) {
  const router = createMemoryRouter(routes, { initialEntries: [path] });
  await act(async () => {
    root = create(
      <QueryClientProvider client={new QueryClient()}>
        <RouterProvider router={router} />
      </QueryClientProvider>,
    );
  });
  for (let i = 0; i < 6; i++) await act(async () => new Promise((resolve) => setTimeout(resolve, 0)));
  return router;
}
const all = (id: string) => root.root.findAll((n) => typeof n.type === "string" && n.props["data-testid"] === id);
const text = (node: ReactTestInstance | string): string =>
  typeof node === "string" ? node : node.children.map((c) => text(c as ReactTestInstance | string)).join("");
const shown = () => text(root.root);
const homeOf = () => all("route-home")[0]!.props.href as string;

const ROUTER_PAGE = /Unexpected Application Error|Hey developer|404 Not Found/;

describe("an unknown address", () => {
  it.each(["/nope", "/nope/deeper", "/account/nope", "/installation", "/installation/nope", "/device/nope", "/approve", "/o"])("%s is the app's not-found page, in the shell", async (path) => {
    await open(path);
    expect(text(all("not-found")[0]!)).toContain("Page not found");
    expect(all("shell")).toHaveLength(1);
    expect(shown()).not.toMatch(ROUTER_PAGE);
    expect(homeOf()).toBe("/");
    expect(all("route-home")[0]!.props.href).toBeDefined();
  });

  it.each(["/o/acme/nope", "/o/acme/projects/nope", "/o/acme/p", "/o/acme/p/api/nope", "/o/acme/p/api/e", "/o/acme/p/api/e/production/nope", "/o/acme/connections/nope"])("%s is too, and leads back to the Organization", async (path) => {
    await open(path);
    expect(text(all("not-found")[0]!)).toContain("Page not found");
    expect(all("shell")).toHaveLength(1);
    expect(shown()).not.toMatch(ROUTER_PAGE);
    expect(homeOf()).toBe("/o/acme/projects");
  });

  it("shows nothing of the address itself", async () => {
    await open("/o/acme/click-here-to-win");
    expect(shown()).not.toContain("click-here-to-win");
  });

  it("gives way to a page again", async () => {
    const router = await open("/o/acme/nope");
    await act(async () => router.navigate("/o/acme/projects"));
    for (let i = 0; i < 6; i++) await act(async () => new Promise((resolve) => setTimeout(resolve, 0)));
    expect(all("page-projects")).toHaveLength(1);
    expect(all("not-found")).toHaveLength(0);
  });
});

describe("a page that fails", () => {
  it("keeps the shell, says nothing of the error, and offers to reload or go back", async () => {
    fake.throwIn = "projects";
    await open("/o/acme/projects");
    expect(text(all("page-error")[0]!)).toContain("This page could not be shown");
    expect(all("shell")).toHaveLength(1);
    expect(shown()).not.toContain(SECRET);
    expect(shown()).not.toMatch(ROUTER_PAGE);
    expect(homeOf()).toBe("/o/acme/projects");
    const reload = root.root.findAll((n) => n.type === "button" && n.props["data-testid"] === "page-reload")[0]!;
    await act(async () => reload.props.onClick());
    expect(window.location.reload).toHaveBeenCalledTimes(1);
  });

  it("outside the shell has a screen of its own", async () => {
    fake.throwIn = "device";
    await open("/device");
    expect(all("screen-error")).toHaveLength(1);
    expect(shown()).not.toContain(SECRET);
    expect(shown()).not.toMatch(ROUTER_PAGE);
    expect(homeOf()).toBe("/");
  });

  it("the shell itself failing has one too", async () => {
    fake.throwIn = "shell";
    await open("/o/acme/projects");
    expect(all("screen-error")).toHaveLength(1);
    expect(shown()).not.toContain(SECRET);
    expect(shown()).not.toMatch(ROUTER_PAGE);
  });
});

describe("the route table", () => {
  it("has every page it had", () => {
    for (const path of [
      "/", "/credentials", "/profile", "/device", "/approve/apr_1", "/account", "/account/security", "/account/sessions", "/installation/settings",
      "/o/acme", "/o/acme/projects", "/o/acme/p/api", "/o/acme/p/api/contract", "/o/acme/p/api/integrations", "/o/acme/p/api/activity",
      "/o/acme/p/api/e/production", "/o/acme/p/api/e/production/integrations", "/o/acme/p/api/e/production/activity",
      "/o/acme/access", "/o/acme/connections", "/o/acme/connections/github-app", "/o/acme/audit", "/o/acme/security", "/o/acme/settings",
    ]) {
      const matches = matchRoutes(routes, path);
      expect(matches?.at(-1)?.route.path, path).not.toBe("*");
    }
  });

  it("has no address without a page, and an error page above every one", () => {
    for (const path of ["/nope", "/o/acme/nope", "/a/b/c/d", "/o", "/%20"]) expect(matchRoutes(routes, path), path).not.toBeNull();
    expect(routes.every((r) => r.errorElement !== undefined)).toBe(true);
  });
});
