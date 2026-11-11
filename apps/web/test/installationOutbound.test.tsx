// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestInstance, type ReactTestRenderer } from "react-test-renderer";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { InstallationOutbound } from "@varlatch/protocol";

/**
 * Installation → Outbound (ADR-0057 Decision 8): the host's allow list as
 * parsed, read-only, with doctor's warnings, saying it is set on the host;
 * every refused destination by Organization with its reason; and the line
 * that would allow the refused names. Only Installation Admins ask for it.
 */

const fake = vi.hoisted(() => ({ api: {} as Record<string, (...args: never[]) => unknown> }));
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
vi.mock("../src/shell/Shell", () => ({ errorMessage: (err: unknown) => (err instanceof Error ? err.message : String(err)) }));

import { OutboundReport } from "../src/features/installation/OutboundTab";
import { InstallationPage } from "../src/features/installation/InstallationPage";

const acme = { id: "org_a", slug: "acme", name: "Acme" };
const beta = { id: "org_b", slug: "beta", name: "Beta" };

const OUTBOUND: InstallationOutbound = {
  generatedAt: "2026-11-11T12:00:00.000Z",
  allow: ["sink.example:9999", "127.0.0.1/32"],
  warnings: ["127.0.0.1/32 opens a host-only range (loopback, link-local or metadata) to every Organization"],
  refused: [
    { organization: acme, kind: "webhook", id: "wh_1", name: null, scheme: "https", host: "hooks.lan", port: 443, reason: "private_address", notSuggested: null },
    {
      organization: acme,
      kind: "coolify",
      id: "pc_1",
      name: "Production Coolify",
      scheme: "https",
      host: "coolify.lan",
      port: 8443,
      reason: "private_address",
      notSuggested: null,
    },
    {
      organization: beta,
      kind: "webhook",
      id: "wh_2",
      name: null,
      scheme: "https",
      host: "metadata.lan",
      port: 443,
      reason: "host_only_address",
      notSuggested: "resolves to a loopback, link-local, metadata or reserved address, which a hostname entry never opens",
    },
  ],
  suggested: "sink.example:9999,127.0.0.1/32,hooks.lan,coolify.lan:8443",
  checked: 6,
  unresolved: 0,
};

let root: ReactTestRenderer | undefined;
afterEach(async () => {
  await act(async () => root?.unmount());
  root = undefined;
});
const all = (id: string) => root!.root.findAll((n) => typeof n.type === "string" && n.props["data-testid"] === id);
const text = (node: ReactTestInstance | string): string =>
  typeof node === "string" ? node : node.children.map((c) => text(c as ReactTestInstance | string)).join("");
const one = (id: string) => {
  const found = all(id);
  if (found.length !== 1) throw new Error(`${found.length} elements with data-testid ${id}`);
  return text(found[0]!);
};
async function show(outbound: InstallationOutbound) {
  await act(async () => {
    root = create(
      <MemoryRouter>
        <OutboundReport outbound={outbound} />
      </MemoryRouter>,
    );
  });
}

describe("Outbound tab", () => {
  it("shows the allow list as parsed, says it is set on the host, and shows doctor's warnings", async () => {
    await show(OUTBOUND);
    const allow = one("outbound-allow");
    expect(allow).toContain("Set on the host as VARLATCH_OUTBOUND_ALLOW");
    expect(allow).toContain("cannot be changed here");
    expect(one("outbound-allow-entries")).toBe("sink.example:9999127.0.0.1/32");
    expect(one("outbound-warning")).toContain("127.0.0.1/32 opens a host-only range");
    // Read-only: nothing to edit; the only button copies the suggested line.
    expect(root!.root.findAll((n) => n.type === "input" || n.type === "textarea" || n.type === "select")).toHaveLength(0);
    expect(root!.root.findAll((n) => n.type === "button")).toHaveLength(1);
  });

  it("lists every refused destination by Organization with kind, name, host and reason", async () => {
    await show(OUTBOUND);
    const row = (id: string) => [...all(`outbound-refused-${id}`)[0]!.findAllByType("td")].map((td) => text(td));
    expect(row("wh_1")).toEqual(["Acme", "Webhook", "wh_1", "https://hooks.lan:443", "private network address"]);
    // The Organization is named once per group.
    expect(row("pc_1")).toEqual(["", "Coolify", "Production Coolify", "https://coolify.lan:8443", "private network address"]);
    expect(row("wh_2")[0]).toBe("Beta");
    expect(row("wh_2")[4]).toBe("loopback or link-local addressresolves to a loopback, link-local, metadata or reserved address, which a hostname entry never opens");
  });

  it("gives the suggested line to add on the host", async () => {
    await show(OUTBOUND);
    expect(one("outbound-suggested-line")).toContain("VARLATCH_OUTBOUND_ALLOW=sink.example:9999,127.0.0.1/32,hooks.lan,coolify.lan:8443");
    expect(one("outbound-suggested")).toContain("restart varlatchd");
  });

  it("says when nothing is set and nothing is refused", async () => {
    await show({ ...OUTBOUND, allow: [], warnings: [], refused: [], suggested: null, unresolved: 0 });
    expect(one("outbound-allow-empty")).toContain("Not set");
    expect(all("outbound-warning")).toHaveLength(0);
    expect(one("outbound-refused-none")).toBe("None. Every configured destination is allowed.");
    expect(all("outbound-suggested")).toHaveLength(0);
    await show({ ...OUTBOUND, refused: [], suggested: null, checked: 0 });
    expect(one("outbound-refused-none")).toContain("No Organization has configured");
  });

  it("never reads destinations it could not check as allowed", async () => {
    await show({ ...OUTBOUND, refused: [], suggested: null, unresolved: 2 });
    expect(one("outbound-refused-none")).toBe("None of those checked.");
    expect(one("outbound-unchecked")).toContain("2 of 6 configured destinations could not be checked");
    await show({ ...OUTBOUND, unresolved: 1 });
    expect(all("outbound-refused-wh_1")).toHaveLength(1);
    expect(one("outbound-unchecked")).toContain("1 of 6 configured destinations could not be checked: its name did not resolve");
  });
});

describe("the Installation page's Outbound tab", () => {
  async function page(backups: () => Promise<unknown>, capabilities = ["installation.outbound"]) {
    const getInstallationOutbound = vi.fn(async () => OUTBOUND);
    fake.api = {
      meta: async () => ({ apiMajor: 1, serverVersion: "0.21.1", capabilities }),
      getInstallationBackups: backups,
      getInstallationOutbound,
    };
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    await act(async () => {
      root = create(
        <QueryClientProvider client={client}>
          <MemoryRouter initialEntries={["/installation/settings?tab=outbound"]}>
            <InstallationPage />
          </MemoryRouter>
        </QueryClientProvider>,
      );
    });
    for (let i = 0; i < 5; i++) await act(async () => void (await new Promise((r) => setTimeout(r, 0))));
    return getInstallationOutbound;
  }

  it("asks nothing when the admin-only backups read is refused, and says why", async () => {
    expect(await page(async () => Promise.reject(new Error("Installation Admin required")))).not.toHaveBeenCalled();
    expect(one("outbound-error")).toContain("Installation Admin authority is required");
  });

  it("asks once that read succeeded, and shows the policy", async () => {
    expect(await page(async () => ({ archives: [], warnings: [] }))).toHaveBeenCalledOnce();
    expect(all("outbound-refused-wh_1")).toHaveLength(1);
  });

  it("never asks a server without the capability", async () => {
    expect(await page(async () => ({ archives: [], warnings: [] }), [])).not.toHaveBeenCalled();
    expect(one("outbound-error")).toContain("does not report its outbound policy");
  });
});
