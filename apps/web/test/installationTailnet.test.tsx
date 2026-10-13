// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestInstance, type ReactTestRenderer } from "react-test-renderer";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { InstallationListeners, TailnetListenerReport } from "@varlatch/protocol";

/**
 * Installation → Tailnet shows what varlatchd reports of its tailnet
 * listeners, and what the operator runs on the host. It never presents a
 * configured tailnet as working, and the report's one check time is shown
 * once, for all checks.
 */

const fake = vi.hoisted(() => ({ api: {} as Record<string, (...args: never[]) => unknown> }));
vi.hoisted(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  // useNow ticks and CopyButton resets with window timers; nothing else here needs a browser.
  const g = globalThis;
  vi.stubGlobal("window", {
    setInterval: g.setInterval.bind(g),
    clearInterval: g.clearInterval.bind(g),
    setTimeout: g.setTimeout.bind(g),
    clearTimeout: g.clearTimeout.bind(g),
  });
});
vi.mock("../src/lib/session", () => ({ useSession: () => ({ api: fake.api }) }));

import {
  LISTENERS_STALE_MS,
  NODE_PLACEHOLDER,
  checkRows,
  enableEndpointLines,
  endpointRule,
  remedy,
  tailnetSummary,
} from "../src/features/installation/tailnetStatus";
import { TailnetTab } from "../src/features/installation/TailnetTab";

const NOW = Date.parse("2026-10-13T12:00:00Z");
const ago = (ms: number) => new Date(NOW - ms).toISOString();

const report = (over: Partial<TailnetListenerReport["observed"]["checks"]> = {}, checkedAt: string | null = ago(30_000)): TailnetListenerReport => ({
  configured: { tailnet: "example.ts.net", listenerPort: 8687, browserEndpoint: "https://varlatch.example.ts.net:8688" },
  observed: {
    checkedAt,
    checks: {
      listener: { status: "pass" },
      browserTls: { status: "pass", certificateNotAfter: "2027-01-01T00:00:00Z" },
      localApi: { status: "pass" },
      node: { status: "pass" },
      ...over,
    },
  },
});
const withoutEndpoint = (): TailnetListenerReport => {
  const r = report();
  const { browserTls: _tls, ...checks } = r.observed.checks;
  return { configured: { ...r.configured, browserEndpoint: null }, observed: { ...r.observed, checks } };
};

describe("tailnetSummary", () => {
  it("says nothing works before the first check", () => {
    expect(tailnetSummary(report({}, null), NOW)).toEqual({ tone: "muted", headline: "Not checked yet", stale: false });
  });

  it("passes only when every check passes", () => {
    expect(tailnetSummary(report(), NOW)).toMatchObject({ tone: "ok", headline: "All server checks pass" });
    expect(tailnetSummary(report({ node: { status: "unknown", reason: "NOT_CHECKED" } }), NOW)).toMatchObject({ tone: "muted" });
    expect(tailnetSummary(report({ browserTls: { status: "fail", reason: "NO_CERTIFICATE" } }), NOW)).toMatchObject({
      tone: "error",
      headline: "1 of 4 checks fail",
    });
  });

  it("flags a report older than the doctor's limit, whatever it says", () => {
    expect(tailnetSummary(report({}, ago(LISTENERS_STALE_MS + 1)), NOW)).toMatchObject({ tone: "warn", stale: true });
    expect(tailnetSummary(report({}, ago(LISTENERS_STALE_MS - 1)), NOW)).toMatchObject({ tone: "ok", stale: false });
  });
});

describe("checkRows", () => {
  it("lists the certificate only with the browser endpoint", () => {
    expect(checkRows(report()).map((r) => r.key)).toEqual(["listener", "localApi", "node", "browserTls"]);
    expect(checkRows(withoutEndpoint()).map((r) => r.key)).toEqual(["listener", "localApi", "node"]);
    expect(checkRows(withoutEndpoint())[0]!.passes).toBe("The tailnet listener (port 8687) is bound");
  });
});

describe("guidance", () => {
  it("gives the grant setup prints, with a placeholder for the node", () => {
    expect(JSON.parse(endpointRule("https://varlatch.example.ts.net:8688"))).toEqual({
      src: ["autogroup:member"],
      dst: [NODE_PLACEHOLDER],
      ip: ["tcp:8688"],
    });
    expect(JSON.parse(endpointRule("https://varlatch.example.ts.net:9443")).ip).toEqual(["tcp:9443"]);
    expect(JSON.parse(endpointRule(null)).ip).toEqual(["tcp:8688"]);
  });

  it("fills in the configured tailnet, never the machine name it cannot know", () => {
    expect(enableEndpointLines("coolify", "example.ts.net")).toContain("VARLATCH_TAILNET_ENDPOINT=https://<machine>.example.ts.net:8688");
    expect(enableEndpointLines("coolify", null)).toContain("VARLATCH_TAILNET_ENDPOINT=https://<machine>.<your-tailnet>.ts.net:8688");
    expect(enableEndpointLines("setup", "example.ts.net")).toEqual(["varlatch setup --dir /srv/varlatch --tailnet-endpoint"]);
  });

  it("says what to change for each deployment", () => {
    expect(remedy("NOT_CHECKED", "setup")).toBeNull();
    expect(remedy("NOT_RUNNING", "setup")).toBe("Inspect: docker compose logs tailscale varlatchd");
    expect(remedy("NAME_CHANGED", "coolify")).toMatch(/VARLATCH_TAILNET_NODE and VARLATCH_TAILNET_ENDPOINT/);
    expect(remedy("NO_CERTIFICATE", "coolify")).toMatch(/VARLATCH_TAILNET_CERT_UID must be 999/);
  });
});

let root: ReactTestRenderer;
async function mount(listeners: () => Promise<InstallationListeners>) {
  vi.useFakeTimers({ now: NOW, toFake: ["Date"] });
  fake.api = { getInstallationListeners: listeners };
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => {
    root = create(
      <QueryClientProvider client={client}>
        <MemoryRouter>
          <TailnetTab />
        </MemoryRouter>
      </QueryClientProvider>,
    );
  });
  // The query settles, then React Query notifies on a later tick.
  for (let i = 0; i < 5; i++) await act(async () => void (await new Promise((r) => setTimeout(r, 0))));
}
afterEach(async () => {
  await act(async () => root?.unmount());
  vi.useRealTimers();
});
const all = (id: string) => root.root.findAll((n) => typeof n.type === "string" && n.props["data-testid"] === id);
const byTestId = (id: string): ReactTestInstance => {
  const found = all(id);
  if (found.length !== 1) throw new Error(`${found.length} elements with data-testid ${id}`);
  return found[0]!;
};
const text = (node: ReactTestInstance | string): string =>
  typeof node === "string" ? node : node.children.map((c) => text(c as ReactTestInstance | string)).join("");
const row = (key: string) => root.root.find((n) => n.type === "tr" && n.props["data-check"] === key);

describe("Tailnet tab", () => {
  it("without a tailnet listener, claims nothing about Tailscale on the host and shows how to add it", async () => {
    await mount(async () => ({ tailnet: null }));
    expect(text(byTestId("tailnet-not-configured"))).toContain("No tailnet listener configured in Varlatch");
    expect(text(byTestId("tailnet-not-configured"))).toContain("does not tell whether Tailscale is installed or joined elsewhere");
    expect(all("tailnet-checks")).toHaveLength(0);
    expect(text(byTestId("tailnet-add-lines"))).toContain("--tailnet-endpoint");
    expect(text(byTestId("tailnet-guidance"))).toContain("Switching an existing installation to the tailnet ingress is not supported");

    await act(async () => byTestId("tailnet-deployment-coolify").props.onClick());
    expect(text(byTestId("tailnet-add-lines"))).toContain("docker-compose.coolify-tailscale.yml");
    expect(text(byTestId("tailnet-endpoint-lines"))).toContain("VARLATCH_TAILNET_CERT_UID=999");
  });

  it("shows one check time for the whole report, each check's result, and the fix for the chosen deployment", async () => {
    await mount(async () => ({ tailnet: report({ node: { status: "fail", reason: "NAME_CHANGED" } }, ago(4 * 60_000)) }));
    expect(all("tailnet-checked-at")).toHaveLength(1);
    expect(text(byTestId("tailnet-checked-at"))).toBe("Last checked 4m ago");
    expect(byTestId("tailnet-summary").props["data-tone"]).toBe("error");
    expect(row("listener").props["data-status"]).toBe("pass");
    expect(row("node").props["data-status"]).toBe("fail");
    expect(text(row("node"))).toContain("The node's name is no longer the browser endpoint's host");
    expect(text(row("node"))).toContain("Rerun varlatch setup");
    expect(text(row("browserTls"))).toContain("Certificate valid until");
    expect(all("tailnet-stale")).toHaveLength(0);
    expect(text(byTestId("tailnet-server-side"))).toContain("only that device can find out");

    await act(async () => byTestId("tailnet-deployment-coolify").props.onClick());
    expect(text(row("node"))).toContain("VARLATCH_TAILNET_NODE and VARLATCH_TAILNET_ENDPOINT");
    expect(text(byTestId("tailnet-rule"))).toContain("tcp:8688");
  });

  it("flags an old report and offers the endpoint when it is off", async () => {
    const old = withoutEndpoint();
    old.observed.checkedAt = ago(LISTENERS_STALE_MS + 60_000);
    await mount(async () => ({ tailnet: old }));
    expect(all("tailnet-stale")).toHaveLength(1);
    expect(byTestId("tailnet-summary").props["data-tone"]).toBe("warn");
    expect(text(byTestId("tailnet-endpoint"))).toBe("Off");
    expect(text(byTestId("tailnet-endpoint-lines"))).toContain("varlatch setup --dir /srv/varlatch --tailnet-endpoint");
  });

  it("says when the report cannot be read", async () => {
    await mount(async () => {
      throw new Error("Installation Admin required");
    });
    expect(text(byTestId("tailnet-error"))).toContain("Installation Admin required");
  });
});
