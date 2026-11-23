// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestInstance, type ReactTestRenderer } from "react-test-renderer";
import { createMemoryRouter, matchRoutes, Outlet, RouterProvider, type RouteObject } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { isNotFound } from "../src/shell/notFound";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * The route table (src/app.tsx): an unknown address shows the app's own
 * page, in the shell; a page that fails shows a page of the app too, and
 * never what the error says. The router's own error page ("Unexpected
 * Application Error!") must not show anywhere.
 */

const SECRET = "postgres://db.internal: a detail of the failure";
const fake = vi.hoisted(() => ({
  throwIn: "",
  orgs: (async () => ({ items: [] })) as () => Promise<{ items: { slug: string }[] }>,
  asked: 0,
  focused: [] as string[],
}));
vi.hoisted(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  vi.stubGlobal("window", { __VARLATCH__: {}, location: { reload: vi.fn() } });
  vi.stubGlobal("document", { title: "Varlatch" });
});
vi.mock("../src/lib/backend", () => ({ backend: () => ({ session: "varlatch", realtime: "sse" }) }));
vi.mock("../src/lib/session", () => ({ SessionProvider: ({ children }: { children: React.ReactNode }) => children, useSession: () => ({ api: { listOrganizations: () => (fake.asked++, fake.orgs()) } }) }));
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
  fake.orgs = async () => ({ items: [{ slug: "acme" }] });
  fake.asked = 0;
  fake.focused = [];
  document.title = "Varlatch";
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
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <RouterProvider router={router} />
      </QueryClientProvider>,
      { createNodeMock: (element) => ({ focus: () => void fake.focused.push(String((element.props as Record<string, unknown>)["data-testid"])) }) },
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

describe("the way back", () => {
  it.each([
    ["an Organization that does not exist or is not theirs", async () => ({ items: [{ slug: "other" }] })],
    ["no Organization at all", async () => ({ items: [] })],
    ["the list on its way", () => new Promise<never>(() => {})],
    ["a list that could not be read", async () => Promise.reject(new Error(SECRET))],
  ] as const)("is the start page with %s", async (_, orgs) => {
    fake.orgs = orgs as typeof fake.orgs;
    await open("/o/does-not-exist/nope");
    expect(homeOf()).toBe("/");
    expect(shown()).not.toContain(SECRET);
  });
});

describe("the not-found page", () => {
  it("names the document and takes the focus, and gives the name back", async () => {
    const router = await open("/o/acme/nope");
    expect(document.title).toBe("Page not found · Varlatch");
    expect(fake.focused).toEqual(["route-heading"]);
    const heading = all("route-heading")[0]!;
    expect([heading.props.role, heading.props["aria-level"], heading.props.tabIndex]).toEqual(["heading", 1, -1]);
    // Another address without a page: the same screen, focused again.
    await act(async () => router.navigate("/o/acme/nope-again"));
    expect(fake.focused).toEqual(["route-heading", "route-heading"]);
    await act(async () => router.navigate("/o/acme/projects"));
    for (let i = 0; i < 6; i++) await act(async () => new Promise((resolve) => setTimeout(resolve, 0)));
    expect(document.title).toBe("Varlatch");
  });

  it("is marked for the shell, and only it is", () => {
    for (const path of ["/nope", "/o/acme/nope", "/o/acme/p/api/nope"]) expect(isNotFound(matchRoutes(routes, path)!.map((m) => ({ handle: m.route.handle }))), path).toBe(true);
    for (const path of ["/", "/account", "/o/acme/projects", "/o/acme/p/api", "/o/acme/security"]) expect(isNotFound(matchRoutes(routes, path)!.map((m) => ({ handle: m.route.handle }))), path).toBe(false);
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
    expect(document.title).toBe("This page could not be shown · Varlatch");
    expect(fake.focused).toEqual(["route-heading"]);
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

  it("the shell itself failing has one too, which asks the server nothing", async () => {
    fake.throwIn = "shell";
    await open("/o/acme/projects");
    expect(all("screen-error")).toHaveLength(1);
    expect(fake.asked).toBe(0);
    expect(homeOf()).toBe("/");
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
